
targets=lighthouse host1 host2

.PHONY: $(targets) log-$(targets)

$(targets):
	@make -f makefile.base run name=$@

image:
	@docker build -t nebula .

nebula-net:
	@docker network create --subnet=172.20.0.0/24 nebula

bin:
	@cd .. && $(MAKE) bin

clean:
	@rm -rf ${targets}