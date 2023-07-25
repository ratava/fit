from setuptools import setup

setup(
	name="fit",
	version="0.1",
	py_modules=['fit'],
	install_requires=[
		'click', 'requests',
	],
	entry_points='''
		[console_scripts]
		fit=fit.cli
	''',

)
