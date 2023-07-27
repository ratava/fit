from setuptools import setup

setup(
	name="fit",
	version="0.25",
	py_modules=['fit'],
	install_requires=[
		'click', 'requests', 'selenium', 'requests_toolbelt'
	],
	entry_points='''
		[console_scripts]
		fit=fit.cli
	''',

)
