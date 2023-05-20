import logging
import time
import maat
from copy import deepcopy


class PISEAttributes:
    def __init__(self, inputs):
        self.inputs = inputs
        self.idx = 0
        self.indices = []
        self.state_manager = maat.SimpleStateManager("./tmp")
        self._solvers = [maat.Solver()]
        self.solver = self._solvers[-1]

    def save_engine_state(self, engine: maat.MaatEngine) -> None:
        self.state_manager.enqueue_state(engine)
        sl = deepcopy(self.solver)
        self._solvers.append(sl)
        self.solver = self._solvers[-1]
        self.indices.append(self.idx)

    def pop_engine_state(self) -> (bool, maat.MaatEngine):
        self._solvers = self._solvers[:-1]
        self.solver = self._solvers[-1]
        engine = maat.MaatEngine(maat.ARCH.X64)
        pop_success = self.state_manager.dequeue_state(engine)
        if pop_success:
            self.idx = self.indices[-1]
            self.indices = self.indices[:-1]
        return pop_success, engine

    def execute_branch_callback(self, engine: maat.MaatEngine):
        cond = None
        if engine.info.branch.taken:
            cond = engine.info.branch.cond.invert()
        else:
            cond = engine.info.branch.cond
        sl = deepcopy(self.solver)
        sl.add(cond)
        if sl.check():
            self.save_engine_state(engine)
            self.solver.add(cond)
            engine.vars.update_from(self.solver.get_model())
        return maat.ACTION.CONTINUE

    def make_branch_callback(self):
        return lambda engine: self.execute_branch_callback(engine)
