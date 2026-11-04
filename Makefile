LOCAL = --endpoint-url http://localhost:4566
FAKE = AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1

.PHONY: test moto-up moto-down tf-init tf-apply-local tf-destroy-local scan-local measure-local drift-local

test:
	PYTHONPATH=. python -m pytest -q

# A free fake AWS that runs on your machine. No account, no Docker.
moto-up:
	@moto_server -p 4566 > moto.log 2>&1 & echo $$! > .moto.pid
	@echo "Waiting for the fake AWS..."
	@until curl -s http://localhost:4566/moto-api/ >/dev/null; do sleep 1; done
	@echo "Fake AWS is up on port 4566."

moto-down:
	@kill `cat .moto.pid` && rm -f .moto.pid && echo "Stopped."

tf-init:
	terraform -chdir=terraform init

tf-apply-local:
	$(FAKE) terraform -chdir=terraform apply -auto-approve -var use_emulator=true

tf-destroy-local:
	$(FAKE) terraform -chdir=terraform destroy -auto-approve -var use_emulator=true

scan-local:
	$(FAKE) python -m scanner.cli $(LOCAL) scan --json findings.json

measure-local: scan-local
	$(FAKE) terraform -chdir=terraform output -json planted > planted.json
	python -m scanner.measure planted.json findings.json

drift-local:
	$(FAKE) terraform -chdir=terraform show -json > state.json
	$(FAKE) python -m scanner.cli $(LOCAL) drift --state state.json
