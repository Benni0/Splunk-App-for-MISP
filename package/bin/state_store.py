import os.path as op
import os
import json
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib import client

class BaseStateStore(object):
    def __init__(self, appname):
        self._appname = appname

    def update_state(self, key, states):
        pass

    def get_state(self, key):
        pass

    def delete_state(self, key):
        pass


class FileStateStore(BaseStateStore):
    def __init__(self, appname, checkpoint_dir, key):
        super(FileStateStore, self).__init__(appname)
        self.checkpoint_dir = checkpoint_dir
        self.key = key

        

    def update_state(self, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """

        fname = op.join(self.checkpoint_dir, self.key)
        with open(fname + ".new", "w") as jsonfile:
            json.dump(states, jsonfile)

        if op.exists(fname):
            os.remove(fname)

        os.rename(fname + ".new", fname)
        # commented this to disable state cache for local file
        # if key not in self._states_cache:
        # self._states_cache[key] = {}
        # self._states_cache[key] = states

    def get_state(self):
        fname = op.join(self.checkpoint_dir, self.key)
        if op.exists(fname):
            with open(fname) as jsonfile:
                state = json.load(jsonfile)
                # commented this to disable state cache for local file
                # self._states_cache[key] = state
                return state
        else:
            return None
        
    def get(self, key, default=None):
        state = self.get_state()
        if state and key in state:
            return state[key]
        return default