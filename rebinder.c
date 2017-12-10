#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <pwd.h>
#include <err.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

// This is a very very simple non-conforming nameserver for DNS rebinding
// attacks. Do not use this code for anything important.
//
// Tavis Ormandy <taviso@cmpxchg8b.com>, January 2016

//lint -e754 -e716 -e801

#define __packed __attribute__((packed))

struct qname {
   uint8_t len;
   uint8_t label[8];
} __packed;

struct __packed root {
   struct __packed {
       uint8_t len;        // 5
       uint8_t data[5];    // 'r' 'b' 'n' 'd' 'r'
   } domain;
   struct __packed {
       uint8_t len;        // 2
       uint8_t data[2];    // 'u' 's'
   } tld;
   uint8_t root;           // 0
};

static const struct root kExpectedDomain = {
   .domain = { 5, { 'r', 'b', 'n', 'd', 'r' } },
   .tld    = { 2, { 'u', 's' } },
   .root   = 0,
};

struct __packed header {
   uint16_t id;
   struct __packed {
       unsigned  rd      : 1;
       unsigned  tc      : 1;
       unsigned  aa      : 1;
       unsigned  opcode  : 4;
       unsigned  qr      : 1;
       unsigned  rcode   : 4;
       unsigned  ra      : 1;
       unsigned  ad      : 1;
       unsigned  z       : 2;
   } flags;
   uint16_t qdcount;
   uint16_t ancount;
   uint16_t nscount;
   uint16_t arcount;
   struct __packed {
       struct qname primary;
       struct qname secondary;
       struct root  domain;
   } labels;
   uint16_t qtype;
   uint16_t qclass;
   struct __packed {
       uint8_t flag;
       uint8_t offset;
   } ptr;
   uint16_t type;
   uint16_t class;
   uint32_t ttl;
   uint16_t rdlength;
   struct in_addr rdata;
} __packed;

//lint -efunc(713, parse_ip4_label) Loss of precision (initialization) (unsigned char to char)
bool parse_ip4_label(struct in_addr *out, const uint8_t label[8])
{
    char ip4addr[] = {
        '0', 'x', label[0], label[1],
        label[2], label[3], label[4],
        label[5], label[6], label[7],
        0,
    };

    // Check for invalid characters, lowercase hexadecimal digits only.
    if (strspn(ip4addr + 2, "0123456789abcdef") != 8)
        return false;

    return inet_aton(ip4addr, out) != 0;
}

int main(int argc, char **argv)
{
    struct servent *domain;
    struct passwd *nobody;
    struct sockaddr_in server;
    struct sockaddr_in address;
    struct header reply;
    struct header query;
    socklen_t addrlen;
    time_t querytime;
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        err(EXIT_FAILURE, "failed to create socket");
    }

    if ((domain = getservbyname("domain", "udp")) == NULL) {
        errx(EXIT_FAILURE, "unable to lookup domain properties");
    }

    server.sin_family       = AF_INET;
    server.sin_addr.s_addr  = INADDR_ANY;
    server.sin_port         = domain->s_port; //lint !e734
    addrlen                 = sizeof(address);
    nobody                  = getpwnam("nobody");

    if (nobody == NULL) {
        errx(EXIT_FAILURE, "unable to lookup unprivileged user");
    }

    // Start listening for queries.
    if (bind(sockfd, (struct sockaddr *) &server, sizeof(server)) != 0) {
        errx(EXIT_FAILURE, "unable to bind server");
    }

    // Privileges no longer needed, so change to a chroot directory and setuid.
    if (chdir("/var/empty") != 0 || chroot(".") != 0) {
        errx(EXIT_FAILURE, "unable to change root directory");
    }

    // Change user.
    if (setgid(nobody->pw_gid) != 0 || setuid(nobody->pw_uid) != 0) {
        errx(EXIT_FAILURE, "unable to change to unprivileged user");
    }

    while (true) {
        char clientaddr[INET_ADDRSTRLEN];

        memset(&query, 0, sizeof query);
        memset(&reply, 0, sizeof reply);

        // Attempt to read a DNS query.
        if (recvfrom(sockfd, &query, sizeof query, 0, (struct sockaddr *) &address, &addrlen) < 0) {
            warn("error receiving query packet from network");
            continue;
        }

        // Record time of request.
        time(&querytime); //lint !e534

        // Log query.
        fprintf(stdout, "%s\t%s", inet_ntop(AF_INET, &address.sin_addr, clientaddr, sizeof(clientaddr)), ctime(&querytime));

        // Duplicate the question into answer.
        memcpy(&reply.labels, &query.labels, sizeof reply.labels);

        reply.id            = query.id;
        reply.flags.qr      = true;
        reply.flags.aa      = true;
        reply.ptr.flag      = NS_CMPRSFLGS;
        reply.ptr.offset    = offsetof(struct header, labels);  //lint !e507
        reply.type          = htons(ns_t_a);                    //lint !e641
        reply.class         = htons(ns_c_in);                   //lint !e641
        reply.ttl           = htonl(1);
        reply.rdlength      = htons(sizeof reply.rdata);
        reply.qtype         = query.qtype;
        reply.qclass        = query.qclass;
        reply.qdcount       = query.qdcount;
        reply.ancount       = query.qdcount;


        // Some quick validation.
        if (query.qdcount != htons(1)) {
            warnx("more than one question per query is not supported (%u queries)", ntohs(query.qdcount));
            reply.flags.rcode = ns_r_notimpl; //lint !e641
            goto error;
        }

        // Check that these labels are the right size (8 hexadecimal digits).
        if (query.labels.primary.len != 8) {
            warnx("query with %u byte primary label (must be 8)", query.labels.primary.len);
            reply.flags.rcode = ns_r_nxdomain; //lint !e641
            goto error;
        }

        if (query.labels.secondary.len != 8) {
            warnx("query with %u byte secondary label (must be 8)", query.labels.secondary.len);
            reply.flags.rcode = ns_r_nxdomain; //lint !e641
            goto error;
        }

        // This service is for testing dns rebinding, not free hostnames!
        if (memcmp(query.labels.primary.label, query.labels.secondary.label, 8) == 0) {
            warnx("query with matching labels disallowed to discourage abuse");
            reply.flags.rcode = ns_r_refused; //lint !e641
            goto error;
        }

        // Make sure the root matches.
        if (memcmp(&query.labels.domain, &kExpectedDomain, sizeof kExpectedDomain) != 0) {
            warnx("query for unrecognised domain (must be .rbndr.us)");
            reply.flags.rcode = ns_r_nxdomain; //lint !e641
            goto error;
        }

        // I only support A queries.
        if (query.qtype != htons(ns_t_a)) { //lint !e641
            warnx("unsupported qtype in question, returning no answers (qtype %u)", ntohs(query.qtype));
            goto error;
        }

        // Choose a random label to return based on ID.
        if (!parse_ip4_label(&reply.rdata, (query.id & 1) ? query.labels.primary.label : query.labels.secondary.label)) {
            warnx("client provided an invalid ip4 address, ignoring reqest");
            reply.flags.rcode = ns_r_nxdomain; //lint !e641
            goto error;
        }

        // Send response.
        if (sendto(sockfd, &reply, sizeof reply, 0, (struct sockaddr *) &address, addrlen) != sizeof(reply)) { //lint !e737
            warn("sendto failed to send response to query");
        }

        continue;

  error:
        reply.ancount = 0;

        // Send an empty response (stop after question)
        if (sendto(sockfd,
                   &reply,
                   offsetof(struct header, ptr),                //lint !e507
                   0,
                   (struct sockaddr *) &address,
                   addrlen) != offsetof(struct header, ptr)) {  //lint !e737 !e507
            warn("sendto failed to sending error response to unsupported query");
        }
    }

    //lint -unreachable
    return 0;
}
