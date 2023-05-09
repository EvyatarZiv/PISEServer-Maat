import logging
import time
import maat
from copy import deepcopy


class PISEEngine(maat.MaatEngine):
    def __init__(self, inputs, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inputs = inputs
        self.idx = 0
        self.state_manager = maat.SimpleStateManager("./tmp")
        self._solvers = [maat.Solver()]
        self.solver = self._solvers[-1]

    def save_engine_state(self) -> None:
        self.state_manager.enqueue_state(self)
        sl = deepcopy(self.solver)
        self._solvers.append(sl)
        self.solver = self._solvers[-1]

    def pop_engine_state(self) -> bool:
        self._solvers = self._solvers[:-1]
        self.solver = self._solvers[-1]
        return self.state_manager.dequeue_state(self)

    def branch_callback(self):
        cond = None
        if self.info.branch.taken:
            cond = self.info.branch.cond.invert()
        else:
            cond = self.info.branch.cond
        sl = deepcopy(self.solver)
        sl.add(cond)
        if sl.check():
            self.save_engine_state()
            self.solver.add(cond)
            self.vars.update_from(self.solver.get_model())
        return maat.ACTION.CONTINUE
