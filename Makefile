VENV=python
REQUIREMENTS=requirements.txt
ACTIVATE=source $(VENV)/bin/activate 

all:

python/pyvenv.cfg:
	mkdir -p python
	python3 -m venv $(VENV) && $(ACTIVATE) && pip install -r $(REQUIREMENTS)
	$(ACTIVATE) && pip install --upgrade pip

python: python/pyvenv.cfg

requirements: 
	$(ACTIVATE) && pip freeze > $(REQUIREMENTS)

clean:
	rm -rf $(VENV)