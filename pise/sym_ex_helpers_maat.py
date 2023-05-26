import logging
import time
import maat
from copy import deepcopy
import os
import logging
logger = logging.getLogger(__name__)

TEMP_PATH = "./pise/tmp"

class PISEAttributes:
    def __init__(self, inputs):
        self.inputs = inputs
        self.idx = 0
        self.indices = []
        self.state_manager = maat.SimpleStateManager(TEMP_PATH)
        self._solvers = [[]]
        self.solver = maat.Solver()

    def gen_solver(self) -> maat.Solver:
        if not self._solvers:
            return maat.Solver()
        sl = maat.Solver()
        for cnd in self._solvers[-1]:
            sl.add(cnd)
        return sl

    def gen_conditions(self):
        if not self._solvers:
            return []
        sl = []
        for cnd in self._solvers[-1]:
            sl.append(cnd)
        return sl

    def add_constraint(self, cond: maat.Constraint) -> None:
        self._solvers[-1].append(cond)
        self.solver = self.gen_solver()

    def make_model(self) -> maat.VarContext:
        self.solver.check()
        return self.solver.get_model()

    def save_engine_state(self, engine: maat.MaatEngine) -> None:
        self.state_manager.enqueue_state(engine)
        sl = self.gen_conditions()
        self._solvers = [sl] + self._solvers
        self.indices = [self.idx] + self.indices

    def pop_engine_state(self, engine: maat.MaatEngine) -> (bool, maat.MaatEngine):
        logger.debug("Popping engine")
        self._solvers = self._solvers[:-1]
        self.solver = self.gen_solver()
        pop_success = self.state_manager.dequeue_state(engine)
        if pop_success:
            self.idx = self.indices[-1]
            self.indices = self.indices[:-1]
            engine.vars.update_from(self.make_model())
            logger.debug(engine.cpu.rip)
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
