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

    def save_engine_state(self, engine: maat.MaatEngine) -> None:
        logger.debug(os.getcwd())
        self.state_manager.enqueue_state(engine)
        sl = self.gen_conditions()
        self._solvers.append(sl)
        self.indices.append(self.idx)

    def pop_engine_state(self) -> (bool, maat.MaatEngine):
        self._solvers = self._solvers[:-1]
        self.solver = self.gen_solver()
        engine = maat.MaatEngine(maat.ARCH.X64)
        pop_success = self.state_manager.dequeue_state(engine)
        if pop_success:
            self.idx = self.indices[-1]
            self.indices = self.indices[:-1]
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
            self._solvers[-2].append(cond.invert())
            self._solvers[-1].append(cond)
            self.solver.add(cond)
            self.solver.check()
            # logger.debug(self.solver.check())
            engine.vars.update_from(self.solver.get_model())
        return maat.ACTION.CONTINUE

    def make_branch_callback(self):
        return lambda engine: self.execute_branch_callback(engine)
