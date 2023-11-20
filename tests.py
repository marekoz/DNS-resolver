#author: Marek Kozumplik, xkozum08
import subprocess
import re

test_folder = "tests/"
input_files = ["1.in", "2.in", "3.in", "6.in", "er1.in" ,"er2.in" , "er3.in" ,"x1.in", "x2.in", "x3.in", "x4.in",]  # List of input file names
output_files = ["1.out", "2.out", "3.out", "6.out" ,"er1.out" ,"er2.out" ,"er3.out" , "x1.out", "x2.out", "x3.out", "x4.out"]  # List of output file names

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
    expected_output_re = re.compile(re.escape(case["expected_output"]))
    output2 = re.sub(r'TTL: \d+,', 'TTL: <number>,', output) # Replace TTL
    if expected_output_re.search(output2):
        print(f"Test Passed: ./dns '{case['input']}'")
        i += 1
    else:
        print(f"Test Failed: Input '{case['input']}'")
        print()
        print("Test output: ")
        print(output2)
        print()
        print("Expected output: ")
        print(case["expected_output"])
        print()
        print()

print(str(i)+"/"+str(test_cnt)+" tests passed")

