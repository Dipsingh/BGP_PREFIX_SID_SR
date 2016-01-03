
from twisted.internet import reactor, error

class BGPTimer(object):

    def __init__(self, call_able):
        self.delayed_call = None
        self.callable = call_able

    def cancel(self):
        try:
            self.delayed_call.cancel()
        except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
            pass

    def reset(self, seconds_fromnow):
        try:
            self.delayed_call.reset(seconds_fromnow)
        except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
            self.delayed_call = reactor.callLater(seconds_fromnow, self.callable)

    def active(self):
        try:
            return self.delayed_call.active()
        except AttributeError:
            return False
