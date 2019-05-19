#!/bin/bash
#
# Script to run tests on Travis-CI.
#
# This file is generated by l2tdevtools update-dependencies.py, any dependency
# related changes should be made in dependencies.ini.

# Exit on error.
set -e;

if test "${TRAVIS_OS_NAME}" = "osx";
then
	PYTHONPATH=/Library/Python/2.7/site-packages/ /usr/bin/python ./run_tests.py;

	python ./setup.py build

	python ./setup.py sdist

	python ./setup.py bdist

	if test -f tests/end-to-end.py;
	then
		PYTHONPATH=. python ./tests/end-to-end.py --debug -c config/end-to-end.ini;
	fi

elif test -n "${FEDORA_VERSION}";
then
	CONTAINER_NAME="fedora${FEDORA_VERSION}";
	CONTAINER_OPTIONS="-e LANG=en_US.UTF-8";

	if test -n "${TOXENV}";
	then
		TEST_COMMAND="tox -e ${TOXENV}";

	elif test "${TARGET}" = "pylint";
	then
		TEST_COMMAND="./config/travis/run_pylint.sh";

	elif test ${TRAVIS_PYTHON_VERSION} = "2.7";
	then
		TEST_COMMAND="./config/travis/run_python2.sh";
	else
		TEST_COMMAND="./config/travis/run_python3.sh";
	fi
	# Note that exec options need to be defined before the container name.
	docker exec ${CONTAINER_OPTIONS} ${CONTAINER_NAME} sh -c "cd plaso && ${TEST_COMMAND}";

elif test -n "${UBUNTU_VERSION}";
then
	CONTAINER_NAME="ubuntu${UBUNTU_VERSION}";
	CONTAINER_OPTIONS="-e LANG=en_US.UTF-8";

	if test -n "${TOXENV}";
	then
		TEST_COMMAND="tox -e ${TOXENV}";

	elif test "${TARGET}" = "coverage";
	then
		# Also see: https://docs.codecov.io/docs/testing-with-docker
		curl -o codecov_env.sh -s https://codecov.io/env;

		# Generates a series of -e options.
		CODECOV_ENV=$(/bin/bash ./codecov_env.sh);

		CONTAINER_OPTIONS="${CODECOV_ENV} ${CONTAINER_OPTIONS}";

		TEST_COMMAND="./config/travis/run_coverage.sh";

	elif test "${TARGET}" = "jenkins2";
	then
		TEST_COMMAND="./config/jenkins/linux/run_end_to_end_tests.sh travis";

	elif test "${TARGET}" = "jenkins3";
	then
		TEST_COMMAND="./config/jenkins/linux/run_end_to_end_tests_py3.sh travis";

	elif test "${TARGET}" = "pylint";
	then
		TEST_COMMAND="./config/travis/run_pylint.sh";

	elif test ${TRAVIS_PYTHON_VERSION} = "2.7";
	then
		TEST_COMMAND="./config/travis/run_python2.sh";
	else
		TEST_COMMAND="./config/travis/run_python3.sh";
	fi
	# Note that exec options need to be defined before the container name.
	docker exec ${CONTAINER_OPTIONS} ${CONTAINER_NAME} sh -c "cd plaso && ${TEST_COMMAND}";
fi
