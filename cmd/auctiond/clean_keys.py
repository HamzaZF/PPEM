import os

# List of key file patterns to delete
KEY_FILENAMES = [
    'proving_f10.key',
    'verifying_f10.key',
]

# Root directory (assume script is run from workspace root or adjust as needed)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def find_and_delete_keys():
    deleted = []
    for dirpath, dirnames, filenames in os.walk(ROOT_DIR):
        for fname in filenames:
            if fname in KEY_FILENAMES:
                fpath = os.path.join(dirpath, fname)
                try:
                    os.remove(fpath)
                    deleted.append(fpath)
                except Exception as e:
                    print(f"Failed to delete {fpath}: {e}")
    return deleted

if __name__ == "__main__":
    deleted = find_and_delete_keys()
    if deleted:
        print("Deleted key files:")
        for f in deleted:
            print(f"  {f}")
    else:
        print("No key files found to delete.") 