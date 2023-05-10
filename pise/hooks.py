import logging
import maat

logger = logging.getLogger(__name__)


# This interface describes a callsite that sends/receive messages in the binary, and therefore should be hooked
class SendReceiveCallSite:
    # This function should set the hook within the symbolic execution engine
    # In our case it gets the angr project with the executable loaded
    # Return value is ignored
    def set_hook(self, angr_project):
        raise NotImplementedError()

    # This function should extract the buffer pointer and the buffer length from the program state
    # It is given the call_context as angr's SimProcedure instance, which contains under call_context.state the program state
    # Should return: (buffer, length) tuple
    def extract_arguments(self, call_context):
        raise NotImplementedError()

    # This function should return the suitable return value to simulate a successful send or receive from the callsite
    # It is given the buffer, the length and the call_context (which contains the state)
    # Should return: the return value that will be passed to the caller
    def get_return_value(self, buffer, length, call_context):
        raise NotImplementedError()


class SendHook:
    SEND_STRING = 'SEND'

    def __init__(self, callsite_handler: SendReceiveCallSite, **kwargs):
        # super().__init__(**kwargs) Not clear what the maat equivalent of the old super is...
        self.callsite_handler = callsite_handler

    def execute_callback(self, engine: maat.MaatEngine):
        buffer_arg, length_arg = self.callsite_handler.extract_arguments(engine)
        buffer_addr = buffer_arg.as_uint(ctx=engine.solver.get_model())
        length = length_arg.as_uint(ctx=engine.solver.get_model())
        logger.debug('Send hook with %d bytes, buff = %s' % (length, buffer_addr))

        if engine.inputs[engine.idx].type != SendHook.SEND_STRING:
            return maat.ACTION.HALT

        message_type = engine.inputs[engine.idx]
        engine.mem.make_concolic(buffer_addr, length, 1, "msg_%d" % engine.idx)
        for (offset, value) in message_type.predicate.items():
            offset = int(offset)
            value = int(value)
            if offset >= length:
                return maat.ACTION.HALT
            symb_byte = engine.mem.read(buffer_addr + offset, 1)
            engine.solver.add(symb_byte == value)

        if not engine.solver.check():
            return maat.ACTION.HALT
        return maat.ACTION.CONTINUE

    def make_callback(self):
        return lambda engine: self.execute_callback(engine)


class RecvHook:
    RECEIVE_STRING = 'RECEIVE'

    def __init__(self, callsite_handler: SendReceiveCallSite, **kwargs):
        # super().__init__(**kwargs) Not clear what the maat equivalent of the old super is...
        self.callsite_handler = callsite_handler

    def execute_callback(self, engine: maat.MaatEngine):
        buffer_arg, length_arg = self.callsite_handler.extract_arguments(engine)
        length = length_arg.as_uint(ctx=engine.solver.get_model())
        buffer_addr = buffer_arg.as_uint(ctx=engine.solver.get_model())
        logger.debug('Receive hook with %d bytes, buff = %s' % (length, buffer_addr))
        if engine.inputs[engine.idx].type != RecvHook.RECEIVE_STRING:
            return maat.ACTION.HALT
        message_type = engine.inputs[engine.idx]
        conc_buffer_name = engine.mem.make_concolic(buffer_addr, length, 1, "msg_%d" % engine.idx)
        for (k, v) in message_type.predicate:
            offset = int(k)
            value = int(v)
            if offset >= length:
                return maat.ACTION.HALT  # Received message isn't long enough to match type
            symb_byte = engine.mem.read(buffer_addr+offset, 1)
            engine.solver.add(symb_byte == value)
        return maat.ACTION.CONTINUE

    def make_callback(self):
        return lambda engine: self.execute_callback(engine)


class AsyncHook:
    def resume(self):
        raise NotImplementedError()

    def emulate_recv(self):
        raise NotImplementedError()
