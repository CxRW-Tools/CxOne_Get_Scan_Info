class Operation:
    """Base class for all operations."""

    def __init__(self, config, auth_manager):
        self.config = config
        self.auth = auth_manager

    def execute(self):
        raise NotImplementedError("Operation must implement execute method")
