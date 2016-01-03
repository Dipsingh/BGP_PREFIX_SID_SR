""" BGP Exception """

_FATAL_EXCEPTION_FORMAT_ERRORS = False

class BGPException(Exception):
    """Base BGP Exception"""
    message = "An unknown exception occurred."
    def __init__(self, **kwargs):
        try:
            super(BGPException,self).__init__(self.message % kwargs)
            self.msg = self.message %kwargs
        except Exception:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                super(BGPException,self).__init__(self.message)
    '''
    def __unicode__(self):
        return unicode(self.msg)
    '''

class NotificationSent(Exception):
    """BGP Notification Exception"""

    message = "Unknown Notification exception occured"
    error = 0

    def __init__(self,sub_error,data=''):
        try:
            super(NotificationSent,self).__init__()
            self.msg= self.message % {'sub_error':sub_error,'data':data}
            self.sub_error = sub_error
            self.data = data
        except Exception:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                super(NotificationSent,self).__init__(self.message)
    '''
    def __unicode__(self):
        return unicode(self.msg)
    '''

class MessageHeaderError(NotificationSent):
    error = 1
    message = "BGP Message Header Error, sub error:%(sub_error)s, data:%(data)s"

class OpenMessageError(NotificationSent):
    error = 2
    message = "BGP Open Message Error, sub error:%(sub_error)s, data:%(data)s"

class UpdateMessageError(NotificationSent):
    error = 3
    message = "BGP Update Message Error, sub error:%(sub_error)s, data:%(data)s"

class HoldTimerExpiredError(NotificationSent):
    error = 4
    message = "BGP Hold Timer Expired, sub error:%(sub_error)s, data:%(data)s"

class FSMError(NotificationSent):
    error = 5
    message = "BGP FSM Error, sub error:%(sub_error)s, data:%(data)s"

class ErrCease(NotificationSent):
    error = 6
    message = "BGP ERR CEASE Error, sub error:%(sub_error)s, data:%(data)s"

class ConstructAttributeFailed(BGPException):
    message = 'construct attributes failed, reason :%(reason)s, data=%(data)s'