VENV=python
REQUIREMENTS=requirements.txt
ACTIVATE=source $(VENV)/bin/activate 
TEST_DIR=test
TEST_CONFIG=--config $(TEST_DIR)/test_config.yml
ALIASES=$(TEST_DIR)/test_addresses.dbm
ADDRESS_LIST=$(TEST_DIR)/test_address_list

.PHONY: test

$(ALIASES): $(ADDRESS_LIST)
	./remailer.py --test $(TEST_CONFIG) --makedb < $<

test: $(ALIASES)
	./remailer.py $(TEST_CONFIG) --unittest --unittestdir $(TEST_DIR)

python/pyvenv.cfg:
	mkdir -p python
	python3 -m venv $(VENV) && $(ACTIVATE) && pip install -r $(REQUIREMENTS)
	$(ACTIVATE) && pip install --upgrade pip

python: python/pyvenv.cfg

requirements: 
	$(ACTIVATE) && pip freeze > $(REQUIREMENTS)

clean:
	rm -rf $(VENV)