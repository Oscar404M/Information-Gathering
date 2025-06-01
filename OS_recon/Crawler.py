import os, sys

directory = input("Enter the directory to search in: ")
extension = input("Enter the file extension to search for (ex: .txt): ")
filename = input("Enter the name of the output file: ")

print(f"Searching for {extension} files in {directory}...")

def find_config_files(directory, extension):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(extension):
                print(os.path.join(root, file))

# find_config_files(directory, extension)


with open(filename, 'w') as file:
    original_stdout = sys.stdout
    sys.stdout = file
    find_config_files(directory, extension)
    sys.stdout = original_stdout

print("Output saved to {}".format(filename))