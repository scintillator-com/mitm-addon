
.PHONY: dist
dist:
	python3 setup.py sdist; \
	rm -rf scintillator.egg-info;

