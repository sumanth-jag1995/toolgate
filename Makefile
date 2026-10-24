.PHONY: aws-up aws-down aws-leftovers

aws-up:
	bash scripts/aws_up.sh

aws-down:
	bash scripts/aws_down.sh

aws-leftovers:
	bash scripts/aws_leftovers.sh
