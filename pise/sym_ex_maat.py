#!/usr/bin/env python

from pise import sym_ex_helpers_maat, cache, hooks
import logging
import maat

logger = logging.getLogger('pise')
BASE_ADDR = 0x04000000
LIB64_PATH = "./lib64"
NQUERIES = 0


class QueryRunner:
    def __init__(self, file, callsites_to_monitor, addr_main):
        self.file = file
        self.engine = maat.MaatEngine(maat.ARCH.X64, maat.OS.LINUX)
        self.pise_attr = None
        self.mode = None
        self.engine.load(self.file, maat.BIN.ELF64, libdirs=[LIB64_PATH], load_interp=True, base=BASE_ADDR)
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')
        self.callsites_to_monitor = callsites_to_monitor
        self.addr_main = addr_main
        self.probe_cache = cache.ProbingCache()

        def main_callback(engine):
            return maat.ACTION.HALT

        self.engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, callbacks=[main_callback],
                              filter=self.addr_main + BASE_ADDR)
        self.engine.run()
        sym_ex_helpers_maat.PISEAttributes.gen_init_state(self.engine)
        # logger.debug(self.engine.hooks)

    def set_membership_hooks(self) -> None:
        logger.debug('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(self.engine, self.pise_attr)

    def advance_state(self) -> bool:
        has_next_state, next_state = self.pise_attr.pop_engine_state(self.engine)
        if not has_next_state:
            return False
        self.engine = next_state
        return True

    def do_query_loop(self):
        res = False
        while True:
            """if self.pise_attr.probing:
                logger.debug(self.engine.cpu.rip)"""
            stop_res = self.engine.run()
            if stop_res == maat.STOP.EXIT:
                if not self.advance_state():
                    return res
                continue
            elif stop_res == maat.STOP.HOOK:
                if not self.pise_attr.probing and self.pise_attr.idx == len(self.pise_attr.inputs):
                    logger.debug("MAAT query is true")
                    self.pise_attr.save_engine_state(self.engine, stash_for_probing=True)  # Membership is true
                    res = True
                if not self.advance_state():
                    return res
                continue
            else:
                logger.debug(self.engine.cpu.rip)
                raise NotImplementedError

    def do_monitoring(self) -> bool:
        return self.do_query_loop()

    def do_probing(self) -> list:
        self.pise_attr.new_syms = []
        self.pise_attr.begin_probing()
        if not self.advance_state():
            return []
        logger.debug('Starting probing')
        self.do_query_loop()
        self.probe_cache.insert(self.pise_attr.inputs, self.pise_attr.new_syms)
        return [sym.__dict__ for sym in self.pise_attr.new_syms]

    def membership_step_by_step(self, inputs: list):
        """
        :param inputs: List of MessageTypeSymbol objects
        """
        global NQUERIES
        logger.debug(f'Performed {NQUERIES} queries')
        NQUERIES += 1
        logger.debug('Performing membership, step by step')
        logger.debug('Query: %s' % inputs)
        if self.probe_cache.has_contradiction(inputs):
            logger.debug('Rejected by probing cache')
            return False, None, 0, 0, 0  # Input contains impossible continuation
        self.pise_attr = sym_ex_helpers_maat.PISEAttributes(inputs)
        self.engine = maat.MaatEngine(maat.ARCH.X64, maat.OS.LINUX)
        self.engine.load(self.file, maat.BIN.ELF64, libdirs=[LIB64_PATH], load_interp=True, base=BASE_ADDR)

        logger.debug('Searching cache for prefix:')
        best_pref = self.pise_attr.get_best_cached_prefix(inputs)

        if best_pref is not None:
            self.engine = self.pise_attr.set_cached_state(best_pref, self.engine)
            logger.debug(f'Prefix {best_pref} found!')
            logger.debug(f'{self.engine.cpu.rip}')
            hooks.CallSite.do_ret_from_plt(self.engine)
        else:
            self.engine = sym_ex_helpers_maat.PISEAttributes.set_init_state(self.engine)
            logger.debug('No prefix found')
        self.set_membership_hooks()
        self.engine.hooks.add(maat.EVENT.BRANCH, maat.WHEN.BEFORE,
                              callbacks=[self.pise_attr.make_branch_callback()])
        if len(inputs) > 0 and not self.do_monitoring():
            return False, None, 0, 0, 0  # Membership is false
        if len(inputs) == 0:
            self.pise_attr.save_engine_state(self.engine, stash_for_probing=True)  # Membership is true
        self.pise_attr.cache_state(inputs, self.engine)
        return True, self.do_probing(), 0, 0, 0
