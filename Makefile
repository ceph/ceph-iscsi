DIST ?= "el9"
TAG := $(shell git describe --tags --abbrev=0)
VERSION := $(shell echo $(TAG) | sed 's/^v//')


dist:
	git archive --format=tar.gz --prefix=ceph-iscsi-$(VERSION)/ HEAD > ceph-iscsi-$(VERSION).tar.gz

srpm: dist
	rpmbuild -bs ceph-iscsi.spec \
	  --define "_topdir ." \
	  --define "_sourcedir ." \
	  --define "_srcrpmdir ." \
	  --define "dist .$(DIST)"

.PHONY: dist srpm
