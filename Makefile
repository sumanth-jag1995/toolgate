.PHONY: aws-up aws-down aws-leftovers

aws-up:
	bash scripts/aws_up.sh $(ARGS)

aws-down:
	bash scripts/aws_down.sh $(ARGS)

aws-leftovers:
	bash scripts/aws_leftovers.sh $(ARGS)
