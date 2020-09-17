%bcond_without srpm

%undefine _missing_build_ids_terminate_build

Name:       spool2s3
Version:    0.5.0
Release:    1%{?dist}
Summary:    Continuously spool directory to S3.
URL:        https://github.com/gsauthof/spool2s3
License:    GPLv3+
Source:     https://example.org/spool2s3.tar

BuildRequires: golang-bin
BuildRequires: golang-github-coreos-systemd-devel
BuildRequires: golang-github-fsnotify-devel
BuildRequires: golang-github-jessevdk-flags-devel
BuildRequires: golang-github-jsternberg-zap-logfmt-devel
BuildRequires: golang-github-minio-devel
BuildRequires: golang-uber-zap-devel

%description
Watch a directory, encrypt its files and spool them to an S3 bucket.

%prep
%if %{with srpm}
%autosetup -n spool2s3
%endif

%build
GOPATH=$HOME/go:/usr/share/gocode go build

%install
mkdir -p %{buildroot}/usr/bin
cp spool2s3 %{buildroot}/usr/bin

%check

%files
/usr/bin/spool2s3
%doc README.md


%changelog
* Thu Sep 17 2020 Georg Sauthoff <mail@gms.tf> - 0.5.0-1
- initial packaging

