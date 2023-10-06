import logging
import time
import maat
from copy import deepcopy
import os
import logging

logger = logging.getLogger(__name__)

TEMP_PATH = "./pise/tmp"
INIT_STATE_PATH = "./pise/tmp/init_state"
PROBING_PATH = "./pise/tmp/probing"
NCACHED = 0


class PISEAttributes:
    init_manager = maat.SimpleStateManager(INIT_STATE_PATH)
    state_cache_map = {}

    def __init__(self, inputs):
        self.inputs = inputs
        self.idx = 0
        self.indices = []
        self.probing_indices = []
        self.state_manager = maat.SimpleStateManager(TEMP_PATH)
        self.probing_stash = maat.SimpleStateManager(PROBING_PATH)
        self._solvers = [[]]
        self._probing_solvers = [[]]
        self.solver = maat.Solver()

        self.new_syms = []
        self.probing = False
        self.pending_probe = False

        self.pending_buffer_addr = None
        self.pending_buffer_length = None
        self._pending_queue = []

        self._debug_nstates_enq = 0

    def begin_probing(self):
        self.state_manager = self.probing_stash
        self.indices = self.probing_indices
        self._solvers = self._probing_solvers
        self.probing = True

    @staticmethod
    def gen_init_state(engine):
        PISEAttributes.init_manager.enqueue_state(engine)

    @staticmethod
    def set_init_state(engine):
        assert PISEAttributes.init_manager.dequeue_state(engine)
        PISEAttributes.init_manager.enqueue_state(engine)
        return engine

    def cache_state(self, state, engine):
        global NCACHED
        path = TEMP_PATH + f'/{NCACHED}'
        os.system(f'mkdir {path}')
        logger.debug(f'Caching state with rip={engine.cpu.rip}')
        manager = maat.SimpleStateManager(path)
        manager.enqueue_state(engine)
        PISEAttributes.state_cache_map[tuple(state)] = (
            manager, self.solver, self._solvers[-1:] if self._solvers != [] else [[]], self.idx)
        NCACHED += 1

    def get_best_cached_prefix(self, state):
        best_pref = None
        # logger.debug(f'{state},{PISEAttributes.state_cache_map}')
        for pref in PISEAttributes.state_cache_map.keys():
            if len(pref) < len(state):
                if list(pref) == state[:len(pref)]:
                    if best_pref is None or len(list(best_pref)) < len(list(pref)):
                        best_pref = pref
        return best_pref

    def set_cached_state(self, state, engine):
        entry = PISEAttributes.state_cache_map[state]
        entry[0].dequeue_state(engine)
        entry[0].enqueue_state(engine)
        self.solver = entry[1]
        self._solvers = entry[2]
        assert self._solvers != []
        self.idx = entry[3]
        engine.vars.update_from(self.make_model())
        logging.debug(f'Set to cached state @ {engine.cpu.rip}')
        return engine

    def gen_solver(self) -> maat.Solver:
        if not self._solvers:
            return maat.Solver()
        sl = maat.Solver()
        for cnd in self._solvers[-1]:
            sl.add(cnd)
        return sl

    def gen_conditions(self, for_probing=False):
        if not self._solvers and not for_probing:
            return []
        if not self._probing_solvers and for_probing:
            return []
        sl = []
        cnds = self._probing_solvers[-1] if for_probing else self._solvers[-1]
        for cnd in cnds:
            sl.append(cnd)
        return sl

    def add_constraint(self, cond: maat.Constraint) -> None:
        self._solvers[-1].append(cond)
        self.solver = self.gen_solver()

    def make_model(self) -> maat.VarContext:
        """if not self.solver.check():
            logger.debug(self._solvers[-1])"""
        self.solver.check()
        return self.solver.get_model()

    def save_engine_state(self, engine: maat.MaatEngine, stash_for_probing=False) -> None:
        manager: maat.SimpleStateManager = self.state_manager if not stash_for_probing else self.probing_stash
        solvers = self._solvers if not stash_for_probing else self._probing_solvers
        manager.enqueue_state(engine)
        sl = self.gen_conditions(stash_for_probing)

        self._debug_nstates_enq += not stash_for_probing

        if stash_for_probing:
            self._probing_solvers = [sl] + self._probing_solvers
            self.probing_indices = [self.idx] + self.probing_indices
        else:
            self._solvers = [sl] + self._solvers
            self.indices = [self.idx] + self.indices

        if self.probing or stash_for_probing:
            self._pending_queue = [(self.pending_buffer_addr, self.pending_buffer_length,
                                    self.pending_probe)] + self._pending_queue

        if not stash_for_probing:
            assert (len(self._solvers) == (self._debug_nstates_enq + 1))

    def pop_engine_state(self, engine: maat.MaatEngine) -> (bool, maat.MaatEngine):
        self._solvers = self._solvers[:-1]
        self.solver = self.gen_solver()
        pop_success = self.state_manager.dequeue_state(engine)
        assert (not pop_success or self._solvers != [])
        if pop_success:
            self.idx = self.indices[-1]
            self.indices = self.indices[:-1]
            engine.vars.update_from(self.make_model())
        if self.probing:
            if self._pending_queue:
                self.pending_buffer_addr, self.pending_buffer_length, self.pending_probe = self._pending_queue[-1]
                self._pending_queue = self._pending_queue[:-1]
            else:
                self.pending_buffer_addr, self.pending_buffer_length, self.pending_probe = None, None, False
        return pop_success, engine

    DEBUG_COUNTER = 0

    def execute_branch_callback(self, engine: maat.MaatEngine):
        if not (hasattr(engine.info, 'branch') and hasattr(engine.info.branch, 'cond') and hasattr(engine.info.branch,
                                                                                                   'taken')):
            return maat.ACTION.CONTINUE
        cond = None
        if engine.info.branch.taken:
            # logger.debug("TAKEN")
            cond = engine.info.branch.cond
        else:
            # logger.debug("NOT TAKEN")
            cond = engine.info.branch.cond.invert()
        sl = self.gen_solver()
        sl.add(cond.invert())
        if sl.check():
            # logger.debug('Invert saved')
            self.save_engine_state(engine)
            assert len(self._solvers) > 1
            self._solvers[0].append(cond.invert())
            self._solvers[-1].append(cond)
            self.solver.add(cond)
            if not self.solver.check():
                self.pop_engine_state(engine)
            else:
                engine.vars.update_from(self.make_model())
        return maat.ACTION.CONTINUE

    def make_branch_callback(self):
        return lambda engine: self.execute_branch_callback(engine)
