.PHONY: srpm
srpm:
	dnf -y install git-core
	git archive --prefix spool2s3/ -o spool2s3.tar HEAD
	rpmbuild --define "_sourcedir $$PWD" --define "_specdir $$PWD" --define "_builddir $$PWD" --define "_rpmdir $(outdir)" --define "_srcrpmdir $(outdir)" -bs spool2s3.spec
