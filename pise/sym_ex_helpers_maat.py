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


class PISEAttributes:
    init_manager = maat.SimpleStateManager(INIT_STATE_PATH)

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
        self.reached_next = False
        self.probing = False
        self.pending_probe = False

        self.pending_buffer_addr = None
        self.pending_buffer_length = None
        self._pending_queue = []

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
        self.solver.check()
        return self.solver.get_model()

    def save_engine_state(self, engine: maat.MaatEngine, stash_for_probing=False) -> None:
        manager: maat.SimpleStateManager = self.state_manager if not stash_for_probing else self.probing_stash
        solvers = self._solvers if not stash_for_probing else self._probing_solvers
        manager.enqueue_state(engine)
        sl = self.gen_conditions(stash_for_probing)

        if stash_for_probing:
            self._probing_solvers = [sl] + self._probing_solvers
            self.probing_indices = [self.idx] + self.probing_indices
        else:
            self._solvers = [sl] + self._solvers
            self.indices = [self.idx] + self.indices

        if self.probing or stash_for_probing:
            self._pending_queue = [(self.pending_buffer_addr, self.pending_buffer_length)] + self._pending_queue

    def pop_engine_state(self, engine: maat.MaatEngine) -> (bool, maat.MaatEngine):
        self._solvers = self._solvers[:-1]
        self.solver = self.gen_solver()
        pop_success = self.state_manager.dequeue_state(engine)
        if pop_success:
            self.idx = self.indices[-1]
            self.indices = self.indices[:-1]
            engine.vars.update_from(self.make_model())
        if self.probing:
            self.pending_buffer_addr, self.pending_buffer_length = self._pending_queue[-1]
            self._pending_queue = self._pending_queue[:-1]
        return pop_success, engine

    def execute_branch_callback(self, engine: maat.MaatEngine):
        if not (hasattr(engine.info, 'branch') and hasattr(engine.info.branch, 'cond')):
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
            self.save_engine_state(engine)
            self._solvers[0].append(cond.invert())
            self._solvers[-1].append(cond)
            self.solver.add(cond)
            engine.vars.update_from(self.make_model())
        return maat.ACTION.CONTINUE

    def make_branch_callback(self):
        return lambda engine: self.execute_branch_callback(engine)
