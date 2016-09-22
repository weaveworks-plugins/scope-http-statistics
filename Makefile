.PHONY: run clean

SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")
IMAGE=weavescope-http-statistics-plugin
UPTODATE=.uptodate

run: $(UPTODATE)
	$(SUDO) docker run --rm -it \
	  --privileged --net=host --pid=host \
	  -v /lib/modules:/lib/modules \
	  -v /usr/src:/usr/src \
	  -v /sys/kernel/debug/:/sys/kernel/debug/ \
	  -v /var/run/scope/plugins:/var/run/scope/plugins \
	  --name $(IMAGE) \
	  $(IMAGE)

$(UPTODATE): Dockerfile http-statistics.py ebpf-http-statistics.c
	$(SUDO) docker build -t $(IMAGE) .
	touch $@

clean:
	- rm -rf $(UPTODATE)
	- $(SUDO) docker rmi $(IMAGE)
