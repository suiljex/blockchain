import pickle

class BlockchainFile():
  def __init__(self):
    self.filename = ""

  def save(self, blockchain):
    try:
      f = open(self.filename, "wb")
      pickle.dump(blockchain, f)
      f.close()
      return True
    except Exception as e:
      return False

  def load(self):
    bc = None
    with open(self.filename, "rb") as f:
      bc = pickle.load(f)
    return bc

if __name__ == '__main__':
  print("This module is a dependecy")
  exit(0)