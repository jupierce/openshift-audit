
class Runtime(object):

    def __init__(self, **kwargs):

        for key, val in kwargs.items():
            self.__dict__[key] = val
