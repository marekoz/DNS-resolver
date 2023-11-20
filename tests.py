#author: Marek Kozumplik, xkozum08
import subprocess
import re

test_folder = "tests/"
input_files = ["test1.in", "test2.in", "test3.in"]  # List of input file names
output_files = ["test1.out", "test2.out", "test3.out"]  # List of output file names

test_cases = []
for input_file, output_file in zip(input_files, output_files):
    with open(test_folder+input_file, 'r') as f:
        input_data = f.read().strip()  # Read input from file

    with open(test_folder+output_file, 'r') as f:
        expected_output = f.read().strip()  # Read expected output from file

    test_cases.append({"input": input_data, "expected_output": expected_output})

i = 0
test_cnt = len(input_files)
for case in test_cases:
    command = ["./dns"] + case["input"].split()  # Command to run your app with input arguments
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    output, _ = process.communicate()


    # Check if the output matches the expected output pattern
    expected_output_pattern = re.compile(re.escape(case["expected_output"]))

    # Replace TTL and the number with a placeholder for comparison
    output_without_ttl = re.sub(r'TTL: \d+,', 'TTL: <number>,', output)

    if expected_output_pattern.search(output_without_ttl):
        print(f"Test Passed: ./dns '{case['input']}'")
        i += 1
    else:
        print(f"Test Failed: Input '{case['input']}'")
        print()
        print("Test output: ")
        print(output_without_ttl)
        
        print()
        print("Expected output: ")
        print(case["expected_output"])
        print()
        print()

print(str(i)+"/"+str(test_cnt)+" tests passed")

