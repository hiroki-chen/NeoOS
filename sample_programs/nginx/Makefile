include ../common.mk

NGINX_VERSION	?= 1.22.1
NGINX_URL	?= http://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz
NGINX_TAR	?= nginx-$(NGINX_VERSION).tar.gz
NGINX_BUILD_DIR	?= $(CURDIR)/nginx-$(NGINX_VERSION)
NGINX_BINARY	?= $(NGINX_BUILD_DIR)/nginx

.phony: clean

$(NGINX_BINARY):
	@wget $(NGINX_URL) -O $(NGINX_TAR)
	@tar -xzvf $(NGINX_TAR)
	@echo "Compiling Nginx using CC = $(CC)"
	@sed -i 's/-Wl,-E//' $(NGINX_BUILD_DIR)/auto/cc/conf
	@sed -i 's/ngx_feature_run=yes/ngx_feature_run=no/' $(NGINX_BUILD_DIR)/auto/cc/name
	@sed -i 's/ngx_test="$$CC /ngx_test="gcc /' $(NGINX_BUILD_DIR)/auto/types/sizeof
	@cd $(NGINX_BUILD_DIR) && ./configure --with-cc=$(CC) --with-cc-opt=-static \
		--with-ld-opt=-static --without-pcre --without-http_rewrite_module \
		--without-http_gzip_module --with-poll_module \
		--without-http_upstream_zone_module
	@cd $(NGINX_BUILD_DIR) && $(MAKE) CFLAGS="${CFLGAS} -Wno-error=overflow" -j8
	@cp $(NGINX_BUILD_DIR)/objs/nginx $(OUTPUT_PATH)
	@cp $(CURDIR)/nginx.conf $(OUTPUT_PATH)/..
	@echo "OK"

clean:
	@rm -r $(NGINX_TAR) $(NGINX_BUILD_DIR)
