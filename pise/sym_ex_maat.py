#!/usr/bin/env python

from pise import sym_ex_helpers_maat
import logging
import maat

logger = logging.getLogger(__name__)
BASE_ADDR = 0x04000000
LIB64_PATH = "./lib64"


class QueryRunner:
    def __init__(self, file, callsites_to_monitor, addr_main):
        self.file = file
        self.engine = maat.MaatEngine(maat.ARCH.X64, maat.OS.LINUX)
        self.pise_attr = None
        self.mode = None
        self.engine.load(self.file, maat.BIN.ELF64, libdirs=[LIB64_PATH], load_interp=True, base=BASE_ADDR)
        #logger.debug(self.engine.mem)
        self.callsites_to_monitor = callsites_to_monitor
        self.addr_main = addr_main

        def main_callback(engine):
            return maat.ACTION.HALT

        self.engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, callbacks=[main_callback],
                              filter=self.addr_main + BASE_ADDR)
        self.engine.run()
        sym_ex_helpers_maat.PISEAttributes.gen_init_state(self.engine)

    def set_membership_hooks(self) -> None:
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(self.engine, self.pise_attr)
        self.mode = 'membership'

    def do_monitoring(self) -> bool:
        self.engine = sym_ex_helpers_maat.PISEAttributes.set_init_state(self.engine)
        self.engine.hooks.add(maat.EVENT.BRANCH, maat.WHEN.BEFORE,
                              callbacks=[self.pise_attr.make_branch_callback()])
        while True:
            logger.info('Loop')

            stop_res = self.engine.run()

            logger.info('Stop')
            if stop_res == maat.STOP.EXIT:
                terminated, next_state = self.pise_attr.pop_engine_state(self.engine)
                if not terminated:
                    return False  # Membership is false
                self.engine = next_state
                continue
            elif stop_res == maat.STOP.HOOK:
                if self.pise_attr.idx == len(self.pise_attr.inputs):
                    logger.debug("MAAT query is true")
                    return True  # Membership is true
                else:
                    terminated, next_state = self.pise_attr.pop_engine_state(self.engine)
                    if not terminated:
                        return False  # Membership is false
                    self.engine = next_state
                    continue
            else:
                logger.debug(self.engine.cpu.rip)
                raise NotImplementedError

    def membership_step_by_step(self, inputs: list):
        """
        :param inputs: List of MessageTypeSymbol objects
        """
        logger.info('Performing membership, step by step')
        logger.debug('Query: %s' % inputs)
        self.pise_attr = sym_ex_helpers_maat.PISEAttributes(inputs)

        self.set_membership_hooks()
        if False:
            # Cache, as of yet unimplemented
            raise NotImplementedError
        else:
            # If we haven't found anything in cache, just start from the beginning
            logger.info('No prefix exists in cache, starting from the beginning')
            self.pise_attr.inputs = inputs
        if not self.do_monitoring():
            return False, None, 0, 0, 0  # Membership is false
        return True, None, 0, 0, 0  # TODO: Add probing


