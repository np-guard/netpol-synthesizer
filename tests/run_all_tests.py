"""
Run all tests in a file called "tests.json" (should be located in the current directory
"""

from os import path
import sys
import json
from netpol_synth import netpol_synth_main


def get_output_file_path(test_record, er_file=False):
    """
    Return the path to a test's output file
    :param dict test_record: The test record
    :param bool er_file: Whether to look for the output file in the expected-results dir
    :return: The path to the output file
    :rtype: str
    """
    output_filename = test_record['name']+'.yaml'
    if er_file:
        return path.join('er_files', output_filename)
    return path.join('output_files', output_filename)


def run_netpol_gen(test_record):
    """
    Runs netpol_gen with args taken from the given test
    :param dict test_record: the test record
    :return bool: True if calling netpol_gen_main() was successful,  False otherwise
    """
    args = test_record.get('args', [])
    args += ['-o', get_output_file_path(test_record)]
    args += [path.join('connectivity_jsons', test_record['inputLinks'])]

    args_str = ' '.join(args)
    print(f'Running netpol_gen with args: {args_str}')
    # noinspection PyBroadException
    try:
        netpol_synth_main(args)
        return True
    except BaseException as ex:
        print('Error: Executing netpol_gen failed: ' + str(ex))
        return False


def compare_files(output_filename, golden_filename):
    """
    Compares an output file from this test run to a golden-result file
    :param str output_filename: An output file of the current run
    :param str golden_filename: The golden-result file to compare against
    :return bool: True if files are identical, False otherwise (and prints the first line that has a diff)
    """
    print('Comparing output file {0} to expected-results file {1}'.format(output_filename, golden_filename))
    if not path.isfile(output_filename):
        print(f'Error: Output file {output_filename} not found')
        return False

    with open(output_filename) as output_file:
        output_file_lines = output_file.readlines()

    try:
        with open(golden_filename) as golden_file:
            for golden_file_line_num, golden_file_line in enumerate(golden_file):
                if golden_file_line_num >= len(output_file_lines):
                    print('Error: Expected results have more lines than actual results')
                    return False
                if golden_file_line != output_file_lines[golden_file_line_num]:
                    print('Error: Result mismatch at line {}'.format(golden_file_line_num+1))
                    print(golden_file_line)
                    print(output_file_lines[golden_file_line_num])
                    return False
    except FileNotFoundError:
        print('Error: Expected results file not found')
        return False

    return True


def compare_output_with_er(test_record):
    """
    Compares a specific er_entry against actual run
    :param dict test_record: The full test record
    :return bool: True if actual run files match expected results files, False otherwise
    """
    er_file = get_output_file_path(test_record, True)
    output_file = get_output_file_path(test_record, False)
    return compare_files(output_file, er_file)


def run_test(test_record):
    """
    Runs a single test with given args, and compares its results with golden results
    :param dict test_record: The test details
    :return bool: True if test passed, False otherwise
    """
    if not run_netpol_gen(test_record):
        print('Test failed\n')
        return False

    if not compare_output_with_er(test_record):
        print('Test failed\n')
        return False

    print('Test passed\n')
    return True


if __name__ == '__main__':
    with open('tests.json') as tests_file:
        tests = json.load(tests_file)
        failed_tests = []
        for test_num, test in enumerate(tests, 1):
            test_name = test.get('name')
            print(f'Running test {test_num}: {test_name}')
            if not run_test(test):
                failed_tests.append(test_num)

    if failed_tests:
        print(f'{len(failed_tests)}/{test_num} tests failed: {failed_tests}')
    else:
        print(f'All {test_num} tests passed')
    sys.exit(len(failed_tests) > 0)
