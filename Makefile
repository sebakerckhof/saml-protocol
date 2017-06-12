PROJECT = "@sebak/saml-protocol"

install: ;@echo "install ${PROJECT}"; \
				 yarn;

clean:	;
				rm -rf node_modules

rebuild: ;
	       rm -rf build; tsc;

pretest:	;
					mkdir -p build/test; \
					cp -a test/key test/misc build/test;

doc: ;@echo "prepare and serve the docs"; \
	   docsify serve ./docs

.PHONY: rebuild pretest doc
