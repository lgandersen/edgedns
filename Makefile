REBAR = rebar3
PROJECT = edgedns

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

dialyzer:
	@$(REBAR) dialyzer

check:
	@$(REBAR) do eunit -v, proper -v

shell:
	@$(REBAR) shell

doc:
	@$(REBAR) edoc

rel:
	@$(REBAR) release

console:
	./_build/default/rel/$(PROJECT)/bin/$(PROJECT) console

.PHONY: compile clean dialyzer check shell doc rel console
