uri_configure_depend =				\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install

uri_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra				\
	svm					\
	vlib					\
	vlib-api				\
	vnet					\
	vpp)

uri_LDFLAGS = $(call installed_libs_fn,		\
	vppinfra				\
	svm					\
	vlib					\
	vlib-api				\
	vnet					\
	vpp)
