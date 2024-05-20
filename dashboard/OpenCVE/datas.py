OPENCVEDB_DATA = [
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Apache Tomcat",
                        "vendor": "Apache Software Foundation",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "Apache Tomcat 9 9.0.0.M1 to 9.0.20"
                            },
                            {
                                "status": "affected",
                                "version": "Apache Tomcat 8.5 8.5.0 to 8.5.75"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "If a web application sends a WebSocket message concurrently with the WebSocket connection closing when running on Apache Tomcat 8.5.0 to 8.5.75 or Apache Tomcat 9.0.0.M1 to 9.0.20, it is possible that the application will continue to use the socket after it has been closed. The error handling triggered in this case could cause the a pooled object to be placed in the pool twice. This could result in subsequent connections using the same object concurrently which could result in data being returned to the wrong use and/or other errors."
                    }
                ],
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "other": "high"
                            },
                            "type": "unknown"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-404",
                                "description": "CWE-404 Improper Resource Shutdown or Release",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-07-25T16:53:20",
                    "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
                    "shortName": "apache"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://lists.apache.org/thread/6ckmjfb1k61dyzkto9vm2k5jvt4o7w7c"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://security.netapp.com/advisory/ntap-20220629-0003/"
                    }
                ],
                "source": {
                    "discovery": "UNKNOWN"
                },
                "title": "Response mix-up with WebSocket concurrent send and close",
                "x_generator": {
                    "engine": "Vulnogram 0.0.9"
                },
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "security@apache.org",
                        "ID": "CVE-2022-25762",
                        "STATE": "PUBLIC",
                        "TITLE": "Response mix-up with WebSocket concurrent send and close"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Apache Tomcat",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_affected": "=",
                                                            "version_name": "Apache Tomcat 9",
                                                            "version_value": "9.0.0.M1 to 9.0.20"
                                                        },
                                                        {
                                                            "version_affected": "=",
                                                            "version_name": "Apache Tomcat 8.5",
                                                            "version_value": "8.5.0 to 8.5.75"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "Apache Software Foundation"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "If a web application sends a WebSocket message concurrently with the WebSocket connection closing when running on Apache Tomcat 8.5.0 to 8.5.75 or Apache Tomcat 9.0.0.M1 to 9.0.20, it is possible that the application will continue to use the socket after it has been closed. The error handling triggered in this case could cause the a pooled object to be placed in the pool twice. This could result in subsequent connections using the same object concurrently which could result in data being returned to the wrong use and/or other errors."
                            }
                        ]
                    },
                    "generator": {
                        "engine": "Vulnogram 0.0.9"
                    },
                    "impact": [
                        {
                            "other": "high"
                        }
                    ],
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-404 Improper Resource Shutdown or Release"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://lists.apache.org/thread/6ckmjfb1k61dyzkto9vm2k5jvt4o7w7c",
                                "refsource": "MISC",
                                "url": "https://lists.apache.org/thread/6ckmjfb1k61dyzkto9vm2k5jvt4o7w7c"
                            },
                            {
                                "name": "https://www.oracle.com/security-alerts/cpujul2022.html",
                                "refsource": "MISC",
                                "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
                            },
                            {
                                "name": "https://security.netapp.com/advisory/ntap-20220629-0003/",
                                "refsource": "CONFIRM",
                                "url": "https://security.netapp.com/advisory/ntap-20220629-0003/"
                            }
                        ]
                    },
                    "source": {
                        "discovery": "UNKNOWN"
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
            "assignerShortName": "apache",
            "cveId": "CVE-2022-25762",
            "datePublished": "2022-05-13T07:50:09",
            "dateReserved": "2022-02-22T00:00:00",
            "dateUpdated": "2022-07-25T16:53:20",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2022-42252",
            "assignerOrgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
            "assignerShortName": "apache",
            "dateUpdated": "2022-12-20T13:11:31.015Z",
            "dateReserved": "2022-10-03T00:00:00",
            "datePublished": "2022-11-01T00:00:00"
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "product": "Apache Tomcat",
                        "vendor": "Apache Software Foundation",
                        "versions": [
                            {
                                "lessThanOrEqual": "10.1.0",
                                "status": "affected",
                                "version": "10.1.0-M1",
                                "versionType": "maven"
                            },
                            {
                                "lessThanOrEqual": "10.0.26",
                                "status": "affected",
                                "version": "10.0.0-M1",
                                "versionType": "maven"
                            },
                            {
                                "lessThanOrEqual": "9.0.67",
                                "status": "affected",
                                "version": "9.0.0-M1",
                                "versionType": "maven"
                            },
                            {
                                "lessThanOrEqual": "8.5.82",
                                "status": "affected",
                                "version": "8.5.0",
                                "versionType": "maven"
                            }
                        ]
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "value": "Thanks to Sam Shahsavar who discovered this issue and reported it to the Apache Tomcat security team."
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "If Apache Tomcat 8.5.0 to 8.5.82, 9.0.0-M1 to 9.0.67, 10.0.0-M1 to 10.0.26 or 10.1.0-M1 to 10.1.0 was configured to ignore invalid HTTP headers via setting rejectIllegalHeader to false (the default for 8.5.x only), Tomcat did not reject a request containing an invalid Content-Length header making a request smuggling attack possible if Tomcat was located behind a reverse proxy that also failed to reject the request with the invalid header."
                    }
                ],
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "other": "low"
                            },
                            "type": "unknown"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-444",
                                "description": "CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
                    "shortName": "apache",
                    "dateUpdated": "2022-12-20T13:11:31.015Z"
                },
                "references": [
                    {
                        "url": "https://lists.apache.org/thread/zzcxzvqfdqn515zfs3dxb7n8gty589sq"
                    },
                    {
                        "url": "https://security.gentoo.org/glsa/202305-37"
                    }
                ],
                "source": {
                    "discovery": "UNKNOWN"
                },
                "title": "Apache Tomcat request smuggling via malformed content-length",
                "x_generator": {
                    "engine": "Vulnogram 0.0.9"
                }
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-42794",
            "assignerOrgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
            "state": "PUBLISHED",
            "assignerShortName": "apache",
            "dateReserved": "2023-09-14T12:05:53.583Z",
            "datePublished": "2023-10-10T17:17:01.378Z",
            "dateUpdated": "2023-10-10T17:17:01.378Z"
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "product": "Apache Tomcat",
                        "vendor": "Apache Software Foundation",
                        "versions": [
                            {
                                "lessThanOrEqual": "9.0.80",
                                "status": "affected",
                                "version": "9.0.70",
                                "versionType": "semver"
                            },
                            {
                                "lessThanOrEqual": "8.5.93",
                                "status": "affected",
                                "version": "8.5.85",
                                "versionType": "semver"
                            }
                        ]
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "type": "finder",
                        "value": "Mohammad Khedmatgozar (cellbox)"
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "supportingMedia": [
                            {
                                "base64": False,
                                "type": "text/html",
                                "value": "Incomplete Cleanup vulnerability in Apache Tomcat.<br><br>The internal fork of Commons FileUpload packaged with Apache Tomcat 9.0.70 through 9.0.80 and 8.5.85 through 8.5.93 included an unreleased, \nin progress refactoring that exposed a potential denial of service on \nWindows if a web application opened a stream for an uploaded file but \nfailed to close the stream. The file would never be deleted from disk \ncreating the possibility of an eventual denial of service due to the \ndisk being full.\n<br><p><span style=\"background-color: var(--wht);\">Users are recommended to upgrade to version 9.0.81 onwards or 8.5.94 onwards, which fixes the issue.</span><br></p>"
                            }
                        ],
                        "value": "Incomplete Cleanup vulnerability in Apache Tomcat.\n\nThe internal fork of Commons FileUpload packaged with Apache Tomcat 9.0.70 through 9.0.80 and 8.5.85 through 8.5.93 included an unreleased, \nin progress refactoring that exposed a potential denial of service on \nWindows if a web application opened a stream for an uploaded file but \nfailed to close the stream. The file would never be deleted from disk \ncreating the possibility of an eventual denial of service due to the \ndisk being full.\n\nUsers are recommended to upgrade to version 9.0.81 onwards or 8.5.94 onwards, which fixes the issue.\n\n"
                    }
                ],
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "text": "low"
                            },
                            "type": "Textual description of severity"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-459",
                                "description": "CWE-459 Incomplete Cleanup",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
                    "shortName": "apache",
                    "dateUpdated": "2023-10-10T17:17:01.378Z"
                },
                "references": [
                    {
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://lists.apache.org/thread/vvbr2ms7lockj1hlhz5q3wmxb2mwcw82"
                    },
                    {
                        "url": "http://www.openwall.com/lists/oss-security/2023/10/10/8"
                    }
                ],
                "source": {
                    "discovery": "EXTERNAL"
                },
                "title": "Apache Tomcat: FileUpload: DoS due to accumulation of temporary files on Windows",
                "x_generator": {
                    "engine": "Vulnogram 0.1.0-dev"
                }
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-46589",
            "assignerOrgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
            "state": "PUBLISHED",
            "assignerShortName": "apache",
            "dateReserved": "2023-10-23T08:14:01.046Z",
            "datePublished": "2023-11-28T15:31:52.366Z",
            "dateUpdated": "2023-12-05T09:49:55.646Z"
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "product": "Apache Tomcat",
                        "vendor": "Apache Software Foundation",
                        "versions": [
                            {
                                "lessThanOrEqual": "11.0.0-M10",
                                "status": "affected",
                                "version": "11.0.0-M1",
                                "versionType": "semver"
                            },
                            {
                                "lessThanOrEqual": "10.1.15",
                                "status": "affected",
                                "version": "10.1.0-M1",
                                "versionType": "semver"
                            },
                            {
                                "lessThanOrEqual": "9.0.82",
                                "status": "affected",
                                "version": "9.0.0-M1",
                                "versionType": "semver"
                            },
                            {
                                "lessThanOrEqual": "8.5.95",
                                "status": "affected",
                                "version": "8.5.0",
                                "versionType": "semver"
                            }
                        ]
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "type": "finder",
                        "value": "Norihito Aimoto (OSSTech Corporation) "
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "supportingMedia": [
                            {
                                "base64": False,
                                "type": "text/html",
                                "value": "Improper Input Validation vulnerability in Apache Tomcat.<p>Tomcat <span style=\"background-color: rgb(255, 255, 255);\">from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82 and from 8.5.0 through 8.5.95</span> did not correctly parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to treat a single \nrequest as multiple requests leading to the possibility of request \nsmuggling when behind a reverse proxy.<br></p><p><span style=\"background-color: var(--wht);\">Users are recommended to upgrade to version 11.0.0-M11&nbsp;onwards, 10.1.16 onwards, 9.0.83 onwards or 8.5.96 onwards, which fix the issue.</span></p><br>"
                            }
                        ],
                        "value": "Improper Input Validation vulnerability in Apache Tomcat.Tomcat from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82 and from 8.5.0 through 8.5.95 did not correctly parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to treat a single \nrequest as multiple requests leading to the possibility of request \nsmuggling when behind a reverse proxy.\n\nUsers are recommended to upgrade to version 11.0.0-M11 onwards, 10.1.16 onwards, 9.0.83 onwards or 8.5.96 onwards, which fix the issue.\n\n"
                    }
                ],
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "text": "important"
                            },
                            "type": "Textual description of severity"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-444",
                                "description": "CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
                    "shortName": "apache",
                    "dateUpdated": "2023-12-05T09:49:55.646Z"
                },
                "references": [
                    {
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://lists.apache.org/thread/0rqq6ktozqc42ro8hhxdmmdjm1k1tpxr"
                    },
                    {
                        "url": "https://www.openwall.com/lists/oss-security/2023/11/28/2"
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20231214-0009/"
                    },
                    {
                        "url": "https://lists.debian.org/debian-lts-announce/2024/01/msg00001.html"
                    }
                ],
                "source": {
                    "discovery": "EXTERNAL"
                },
                "title": "Apache Tomcat: HTTP request smuggling via malformed trailer headers",
                "x_generator": {
                    "engine": "Vulnogram 0.1.0-dev"
                }
            }
        }
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "datePublic": "2007-01-11T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Format string vulnerability in the LogMessage function in FileZilla before 3.0.0-beta5 allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via crafted arguments.  NOTE: some of these details are obtained from third party information."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2017-07-28T12:57:01",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "http://sourceforge.net/project/shownotes.php?release_id=477793&group_id=21558"
                    },
                    {
                        "name": "22063",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_BID"
                        ],
                        "url": "http://www.securityfocus.com/bid/22063"
                    },
                    {
                        "name": "ADV-2007-0182",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_VUPEN"
                        ],
                        "url": "http://www.vupen.com/english/advisories/2007/0182"
                    },
                    {
                        "name": "filezilla-logmessage-format-string(31497)",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_XF"
                        ],
                        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/31497"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2007-0317",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Format string vulnerability in the LogMessage function in FileZilla before 3.0.0-beta5 allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via crafted arguments.  NOTE: some of these details are obtained from third party information."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "http://sourceforge.net/project/shownotes.php?release_id=477793&group_id=21558",
                                "refsource": "CONFIRM",
                                "url": "http://sourceforge.net/project/shownotes.php?release_id=477793&group_id=21558"
                            },
                            {
                                "name": "22063",
                                "refsource": "BID",
                                "url": "http://www.securityfocus.com/bid/22063"
                            },
                            {
                                "name": "ADV-2007-0182",
                                "refsource": "VUPEN",
                                "url": "http://www.vupen.com/english/advisories/2007/0182"
                            },
                            {
                                "name": "filezilla-logmessage-format-string(31497)",
                                "refsource": "XF",
                                "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/31497"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2007-0317",
            "datePublished": "2007-01-18T00:00:00",
            "dateReserved": "2007-01-17T00:00:00",
            "dateUpdated": "2017-07-28T12:57:01",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "datePublic": "2007-04-16T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Multiple format string vulnerabilities in FileZilla before 2.2.32 allow remote attackers to execute arbitrary code via format string specifiers in (1) FTP server responses or (2) data sent by an FTP server.  NOTE: some of these details are obtained from third party information."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2008-11-13T10:00:00",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "name": "34437",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_OSVDB"
                        ],
                        "url": "http://osvdb.org/34437"
                    },
                    {
                        "name": "23506",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_BID"
                        ],
                        "url": "http://www.securityfocus.com/bid/23506"
                    },
                    {
                        "name": "24894",
                        "tags": [
                            "third-party-advisory",
                            "x_refsource_SECUNIA"
                        ],
                        "url": "http://secunia.com/advisories/24894"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "http://sourceforge.net/project/shownotes.php?release_id=501534&group_id=21558"
                    },
                    {
                        "name": "34436",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_OSVDB"
                        ],
                        "url": "http://osvdb.org/34436"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2007-2318",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Multiple format string vulnerabilities in FileZilla before 2.2.32 allow remote attackers to execute arbitrary code via format string specifiers in (1) FTP server responses or (2) data sent by an FTP server.  NOTE: some of these details are obtained from third party information."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "34437",
                                "refsource": "OSVDB",
                                "url": "http://osvdb.org/34437"
                            },
                            {
                                "name": "23506",
                                "refsource": "BID",
                                "url": "http://www.securityfocus.com/bid/23506"
                            },
                            {
                                "name": "24894",
                                "refsource": "SECUNIA",
                                "url": "http://secunia.com/advisories/24894"
                            },
                            {
                                "name": "http://sourceforge.net/project/shownotes.php?release_id=501534&group_id=21558",
                                "refsource": "CONFIRM",
                                "url": "http://sourceforge.net/project/shownotes.php?release_id=501534&group_id=21558"
                            },
                            {
                                "name": "34436",
                                "refsource": "OSVDB",
                                "url": "http://osvdb.org/34436"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2007-2318",
            "datePublished": "2007-04-26T21:00:00",
            "dateReserved": "2007-04-26T00:00:00",
            "dateUpdated": "2008-11-13T10:00:00",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "MQ",
                        "vendor": "IBM",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "8.0.0"
                            },
                            {
                                "status": "affected",
                                "version": "9.0.0"
                            },
                            {
                                "status": "affected",
                                "version": "9.1.0"
                            },
                            {
                                "status": "affected",
                                "version": "7.5.0"
                            },
                            {
                                "status": "affected",
                                "version": "9.2.0"
                            }
                        ]
                    }
                ],
                "datePublic": "2021-01-27T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "IBM MQ 7.5, 8.0, 9.0, 9.1, 9.2 LTS, and 9.2 CD could allow a remote attacker to execute arbitrary code on the system, caused by an unsafe deserialization of trusted data. An attacker could exploit this vulnerability to execute arbitrary code on the system. IBM X-Force ID: 186509."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_0": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 8.1,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "HIGH",
                            "exploitCodeMaturity": "UNPROVEN",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "NONE",
                            "remediationLevel": "OFFICIAL_FIX",
                            "reportConfidence": "CONFIRMED",
                            "scope": "UNCHANGED",
                            "temporalScore": 7.1,
                            "temporalSeverity": "HIGH",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.0/AC:H/I:H/S:U/C:H/UI:N/A:H/AV:N/PR:N/RL:O/RC:C/E:U",
                            "version": "3.0"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Gain Access",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2021-01-28T12:55:15",
                    "orgId": "9a959283-ebb5-44b6-b705-dcc2bbced522",
                    "shortName": "ibm"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://www.ibm.com/support/pages/node/6408626"
                    },
                    {
                        "name": "ibm-mq-cve20204682-code-exec (186509)",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_XF"
                        ],
                        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/186509"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "psirt@us.ibm.com",
                        "DATE_PUBLIC": "2021-01-27T00:00:00",
                        "ID": "CVE-2020-4682",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "MQ",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "8.0.0"
                                                        },
                                                        {
                                                            "version_value": "9.0.0"
                                                        },
                                                        {
                                                            "version_value": "9.1.0"
                                                        },
                                                        {
                                                            "version_value": "7.5.0"
                                                        },
                                                        {
                                                            "version_value": "9.2.0"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "IBM"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "IBM MQ 7.5, 8.0, 9.0, 9.1, 9.2 LTS, and 9.2 CD could allow a remote attacker to execute arbitrary code on the system, caused by an unsafe deserialization of trusted data. An attacker could exploit this vulnerability to execute arbitrary code on the system. IBM X-Force ID: 186509."
                            }
                        ]
                    },
                    "impact": {
                        "cvssv3": {
                            "BM": {
                                "A": "H",
                                "AC": "H",
                                "AV": "N",
                                "C": "H",
                                "I": "H",
                                "PR": "N",
                                "S": "U",
                                "UI": "N"
                            },
                            "TM": {
                                "E": "U",
                                "RC": "C",
                                "RL": "O"
                            }
                        }
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "Gain Access"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://www.ibm.com/support/pages/node/6408626",
                                "refsource": "CONFIRM",
                                "title": "IBM Security Bulletin 6408626 (MQ)",
                                "url": "https://www.ibm.com/support/pages/node/6408626"
                            },
                            {
                                "name": "ibm-mq-cve20204682-code-exec (186509)",
                                "refsource": "XF",
                                "title": "X-Force Vulnerability Report",
                                "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/186509"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "9a959283-ebb5-44b6-b705-dcc2bbced522",
            "assignerShortName": "ibm",
            "cveId": "CVE-2020-4682",
            "datePublished": "2021-01-27T00:00:00",
            "dateReserved": "2019-12-30T00:00:00",
            "dateUpdated": "2021-01-28T12:55:15",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "MQ",
                        "vendor": "IBM",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "8.0"
                            },
                            {
                                "status": "affected",
                                "version": "9.0.LTS"
                            },
                            {
                                "status": "affected",
                                "version": "9.1.LTS"
                            },
                            {
                                "status": "affected",
                                "version": "9.1.CD"
                            },
                            {
                                "status": "affected",
                                "version": "9.2.CD"
                            }
                        ]
                    }
                ],
                "datePublic": "2022-08-18T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "IBM MQ 8.0, (9.0, 9.1, 9.2 LTS), and (9.1 and 9.2 CD) are vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 226339."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_0": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "LOW",
                            "baseScore": 8.2,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "HIGH",
                            "exploitCodeMaturity": "UNPROVEN",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "NONE",
                            "remediationLevel": "OFFICIAL_FIX",
                            "reportConfidence": "CONFIRMED",
                            "scope": "UNCHANGED",
                            "temporalScore": 7.1,
                            "temporalSeverity": "HIGH",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.0/AV:N/S:U/A:L/PR:N/UI:N/AC:L/C:H/I:N/RC:C/RL:O/E:U",
                            "version": "3.0"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Gain Access",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-08-19T18:50:09",
                    "orgId": "9a959283-ebb5-44b6-b705-dcc2bbced522",
                    "shortName": "ibm"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://www.ibm.com/support/pages/node/6613021"
                    },
                    {
                        "name": "ibm-mq-cve202222489-xxe (226339)",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_XF"
                        ],
                        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/226339"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "psirt@us.ibm.com",
                        "DATE_PUBLIC": "2022-08-18T00:00:00",
                        "ID": "CVE-2022-22489",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "MQ",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "8.0"
                                                        },
                                                        {
                                                            "version_value": "9.0.LTS"
                                                        },
                                                        {
                                                            "version_value": "9.1.LTS"
                                                        },
                                                        {
                                                            "version_value": "9.1.CD"
                                                        },
                                                        {
                                                            "version_value": "9.2.CD"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "IBM"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "IBM MQ 8.0, (9.0, 9.1, 9.2 LTS), and (9.1 and 9.2 CD) are vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 226339."
                            }
                        ]
                    },
                    "impact": {
                        "cvssv3": {
                            "BM": {
                                "A": "L",
                                "AC": "L",
                                "AV": "N",
                                "C": "H",
                                "I": "N",
                                "PR": "N",
                                "S": "U",
                                "UI": "N"
                            },
                            "TM": {
                                "E": "U",
                                "RC": "C",
                                "RL": "O"
                            }
                        }
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "Gain Access"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://www.ibm.com/support/pages/node/6613021",
                                "refsource": "CONFIRM",
                                "title": "IBM Security Bulletin 6613021 (MQ)",
                                "url": "https://www.ibm.com/support/pages/node/6613021"
                            },
                            {
                                "name": "ibm-mq-cve202222489-xxe (226339)",
                                "refsource": "XF",
                                "title": "X-Force Vulnerability Report",
                                "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/226339"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "9a959283-ebb5-44b6-b705-dcc2bbced522",
            "assignerShortName": "ibm",
            "cveId": "CVE-2022-22489",
            "datePublished": "2022-08-18T00:00:00",
            "dateReserved": "2022-01-03T00:00:00",
            "dateUpdated": "2022-08-19T18:50:09",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Smart eVision",
                        "vendor": "Smart eVision Information Technology Inc.",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "2022.02.21"
                            }
                        ]
                    }
                ],
                "datePublic": "2022-09-28T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Smart eVision has a path traversal vulnerability in the Report API function due to insufficient filtering for special characters in URLs. A remote attacker with general user privilege can exploit this vulnerability to bypass authentication, access restricted paths and download system files."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "NONE",
                            "baseScore": 6.5,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "LOW",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "version": "3.1"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-22",
                                "description": "CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-09-28T03:25:39",
                    "orgId": "cded6c7f-6ce5-4948-8f87-aa7a3bbb6b0e",
                    "shortName": "twcert"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://www.twcert.org.tw/tw/cp-132-6571-fc930-1.html"
                    }
                ],
                "solutions": [
                    {
                        "lang": "en",
                        "value": "Contact tech support from Smart eVision Information Technology Inc."
                    }
                ],
                "source": {
                    "advisory": "TVN-202209007",
                    "discovery": "EXTERNAL"
                },
                "title": "Smart eVision - Path Traversal -2",
                "x_generator": {
                    "engine": "Vulnogram 0.0.9"
                },
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "AKA": "TWCERT/CC",
                        "ASSIGNER": "cve@cert.org.tw",
                        "DATE_PUBLIC": "2022-09-28T03:00:00.000Z",
                        "ID": "CVE-2022-39034",
                        "STATE": "PUBLIC",
                        "TITLE": "Smart eVision - Path Traversal -2"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Smart eVision",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_affected": "=",
                                                            "version_value": "2022.02.21"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "Smart eVision Information Technology Inc."
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Smart eVision has a path traversal vulnerability in the Report API function due to insufficient filtering for special characters in URLs. A remote attacker with general user privilege can exploit this vulnerability to bypass authentication, access restricted paths and download system files."
                            }
                        ]
                    },
                    "generator": {
                        "engine": "Vulnogram 0.0.9"
                    },
                    "impact": {
                        "cvss": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "NONE",
                            "baseScore": 6.5,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "LOW",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "version": "3.1"
                        }
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://www.twcert.org.tw/tw/cp-132-6571-fc930-1.html",
                                "refsource": "MISC",
                                "url": "https://www.twcert.org.tw/tw/cp-132-6571-fc930-1.html"
                            }
                        ]
                    },
                    "solution": [
                        {
                            "lang": "en",
                            "value": "Contact tech support from Smart eVision Information Technology Inc."
                        }
                    ],
                    "source": {
                        "advisory": "TVN-202209007",
                        "discovery": "EXTERNAL"
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "cded6c7f-6ce5-4948-8f87-aa7a3bbb6b0e",
            "assignerShortName": "twcert",
            "cveId": "CVE-2022-39034",
            "datePublished": "2022-09-28T00:00:00",
            "dateReserved": "2022-08-30T00:00:00",
            "dateUpdated": "2022-09-28T03:25:39",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2024-25016",
            "assignerOrgId": "9a959283-ebb5-44b6-b705-dcc2bbced522",
            "state": "PUBLISHED",
            "assignerShortName": "ibm",
            "dateReserved": "2024-02-03T14:48:56.576Z",
            "datePublished": "2024-03-03T03:09:09.906Z",
            "dateUpdated": "2024-03-03T03:09:09.906Z"
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "product": "MQ",
                        "vendor": "IBM",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "9.0 LTS, 9.1 LTS, 9.2 LTS, 9.3 LTS, 9.3 CD"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "supportingMedia": [
                            {
                                "base64": False,
                                "type": "text/html",
                                "value": "IBM MQ and IBM MQ Appliance 9.0, 9.1, 9.2, 9.3 LTS and 9.3 CD could allow a remote unauthenticated attacker to cause a denial of service due to incorrect buffering logic.  IBM X-Force ID:  281279."
                            }
                        ],
                        "value": "IBM MQ and IBM MQ Appliance 9.0, 9.1, 9.2, 9.3 LTS and 9.3 CD could allow a remote unauthenticated attacker to cause a denial of service due to incorrect buffering logic.  IBM X-Force ID:  281279."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "NONE",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "NONE",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en",
                                "value": "GENERAL"
                            }
                        ]
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-20",
                                "description": "CWE-20 Improper Input Validation",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "9a959283-ebb5-44b6-b705-dcc2bbced522",
                    "shortName": "ibm",
                    "dateUpdated": "2024-03-03T03:09:09.906Z"
                },
                "references": [
                    {
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://www.ibm.com/support/pages/node/7123139"
                    },
                    {
                        "tags": [
                            "vdb-entry"
                        ],
                        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/281279"
                    }
                ],
                "source": {
                    "discovery": "UNKNOWN"
                },
                "title": "IBM MQ denial of service",
                "x_generator": {
                    "engine": "Vulnogram 0.1.0-dev"
                }
            }
        }
    },
    {
        "containers": {
            "cna": {
                "title": "Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability",
                "datePublic": "2020-10-13T07:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft Office 2019",
                        "cpes": [
                            "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "19.0.0",
                                "lessThan": "https://aka.ms/OfficeSecurityReleases",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft 365 Apps for Enterprise",
                        "cpes": [
                            "cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "16.0.1",
                                "lessThan": "https://aka.ms/OfficeSecurityReleases",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "<p>A remote code execution vulnerability exists when the Microsoft Office Access Connectivity Engine improperly handles objects in memory. An attacker who successfully exploited this vulnerability could execute arbitrary code on a victim system.</p>\n<p>An attacker could exploit this vulnerability by enticing a victim to open a specially crafted file.</p>\n<p>The update addresses the vulnerability by correcting the way the Microsoft Office Access Connectivity Engine handles objects in memory.</p>\n",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Remote Code Execution",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-31T19:20:23.624Z"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16957"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"
                        }
                    }
                ]
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "cveId": "CVE-2020-16957",
            "datePublished": "2020-10-16T22:18:05",
            "dateReserved": "2020-08-04T00:00:00",
            "dateUpdated": "2023-12-31T19:20:23.624Z",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2024-20677",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "state": "PUBLISHED",
            "assignerShortName": "microsoft",
            "dateReserved": "2023-11-28T22:58:12.117Z",
            "datePublished": "2024-01-09T17:56:45.998Z",
            "dateUpdated": "2024-03-22T23:41:44.959Z"
        },
        "containers": {
            "cna": {
                "title": "Microsoft Office Remote Code Execution Vulnerability",
                "datePublic": "2024-01-09T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "3D Viewer",
                        "cpes": [
                            "cpe:2.3:a:microsoft:3d_viewer:-:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "Unknown"
                        ],
                        "versions": [
                            {
                                "version": "7.0.0",
                                "lessThan": "7.2401.29012.0",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft Office 2019",
                        "cpes": [
                            "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "19.0.0",
                                "lessThan": "https://aka.ms/OfficeSecurityReleases",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft 365 Apps for Enterprise",
                        "cpes": [
                            "cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "16.0.1",
                                "lessThan": "https://aka.ms/OfficeSecurityReleases",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft Office LTSC for Mac 2021",
                        "cpes": [
                            "cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:macos:*:*"
                        ],
                        "platforms": [
                            "Unknown"
                        ],
                        "versions": [
                            {
                                "version": "16.0.1",
                                "lessThan": "16.81.24011420",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft Office LTSC 2021",
                        "cpes": [
                            "cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "16.0.1",
                                "lessThan": "https://aka.ms/OfficeSecurityReleases",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "A security vulnerability exists in FBX that could lead to remote code execution. To mitigate this vulnerability, the ability to insert FBX files has been disabled in Word, Excel, PowerPoint and Outlook for Windows and Mac. Versions of Office that had this feature enabled will no longer have access to it. This includes Office 2019, Office 2021, Office LTSC for Mac 2021, and Microsoft 365. As of February 13, 2024, the ability to insert FBX files has also been disabled in 3D Viewer.\n3D models in Office documents that were previously inserted from a FBX file will continue to work as expected unless the Link to File option was chosen at insert time.\nThis change is effective as of the January 9, 2024 security update.\n",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Remote Code Execution",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-03-22T23:41:44.959Z"
                },
                "references": [
                    {
                        "name": "Microsoft Office Remote Code Execution Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-20677"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2020-19695",
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "dateUpdated": "2023-04-04T00:00:00",
            "dateReserved": "2020-08-13T00:00:00",
            "datePublished": "2023-04-04T00:00:00"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre",
                    "dateUpdated": "2023-04-04T00:00:00"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Buffer Overflow found in Nginx NJS allows a remote attacker to execute arbitrary code via the njs_object_property parameter of the njs/njs_vm.c function."
                    }
                ],
                "affected": [
                    {
                        "vendor": "n/a",
                        "product": "n/a",
                        "versions": [
                            {
                                "version": "n/a",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/nginx/njs/issues/188"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "type": "text",
                                "lang": "en",
                                "description": "n/a"
                            }
                        ]
                    }
                ]
            }
        }
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "njs through 0.7.0, used in NGINX, was discovered to contain an out-of-bounds array access via njs_vmcode_typeof in /src/njs_vmcode.c."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-03-03T10:06:14",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/nginx/njs/issues/450"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://security.netapp.com/advisory/ntap-20220303-0007/"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2021-46461",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "njs through 0.7.0, used in NGINX, was discovered to contain an out-of-bounds array access via njs_vmcode_typeof in /src/njs_vmcode.c."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://github.com/nginx/njs/issues/450",
                                "refsource": "MISC",
                                "url": "https://github.com/nginx/njs/issues/450"
                            },
                            {
                                "name": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2",
                                "refsource": "MISC",
                                "url": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2"
                            },
                            {
                                "name": "https://security.netapp.com/advisory/ntap-20220303-0007/",
                                "refsource": "CONFIRM",
                                "url": "https://security.netapp.com/advisory/ntap-20220303-0007/"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2021-46461",
            "datePublished": "2022-02-14T21:47:17",
            "dateReserved": "2022-01-24T00:00:00",
            "dateUpdated": "2022-03-03T10:06:14",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Nginx NJS v0.7.2 was discovered to contain a segmentation violation in the function njs_set_number at src/njs_value.h."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-05-27T13:13:50",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/nginx/njs/issues/478"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/nginx/njs/commit/5c6130a2a0b4c41ab415f6b8992aa323636338b9"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2022-30503",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Nginx NJS v0.7.2 was discovered to contain a segmentation violation in the function njs_set_number at src/njs_value.h."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://github.com/nginx/njs/issues/478",
                                "refsource": "MISC",
                                "url": "https://github.com/nginx/njs/issues/478"
                            },
                            {
                                "name": "https://github.com/nginx/njs/commit/5c6130a2a0b4c41ab415f6b8992aa323636338b9",
                                "refsource": "MISC",
                                "url": "https://github.com/nginx/njs/commit/5c6130a2a0b4c41ab415f6b8992aa323636338b9"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2022-30503",
            "datePublished": "2022-05-27T13:13:50",
            "dateReserved": "2022-05-09T00:00:00",
            "dateUpdated": "2022-05-27T13:13:50",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "An issue was discovered in Nginx NJS v0.7.5. The JUMP offset for a break instruction was not set to a correct offset during code generation, leading to a segmentation violation."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-08-18T05:08:54",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "http://hg.nginx.org/njs/rev/b7c4e0f714a9"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/nginx/njs/issues/553"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/nginx/njs/commit/404553896792b8f5f429dc8852d15784a59d8d3e"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2022-35173",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "An issue was discovered in Nginx NJS v0.7.5. The JUMP offset for a break instruction was not set to a correct offset during code generation, leading to a segmentation violation."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "http://hg.nginx.org/njs/rev/b7c4e0f714a9",
                                "refsource": "MISC",
                                "url": "http://hg.nginx.org/njs/rev/b7c4e0f714a9"
                            },
                            {
                                "name": "https://github.com/nginx/njs/issues/553",
                                "refsource": "MISC",
                                "url": "https://github.com/nginx/njs/issues/553"
                            },
                            {
                                "name": "https://github.com/nginx/njs/commit/404553896792b8f5f429dc8852d15784a59d8d3e",
                                "refsource": "MISC",
                                "url": "https://github.com/nginx/njs/commit/404553896792b8f5f429dc8852d15784a59d8d3e"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2022-35173",
            "datePublished": "2022-08-18T05:08:54",
            "dateReserved": "2022-07-04T00:00:00",
            "dateUpdated": "2022-08-18T05:08:54",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "datePublic": "2016-07-20T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Integer overflow in the ISO9660 writer in libarchive before 3.2.1 allows remote attackers to cause a denial of service (application crash) or execute arbitrary code via vectors related to verifying filename lengths when writing an ISO9660 archive, which trigger a buffer overflow."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2018-01-04T19:57:01",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "name": "RHSA-2016:1844",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "http://rhn.redhat.com/errata/RHSA-2016-1844.html"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinjul2016-3090544.html"
                    },
                    {
                        "name": "1036431",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_SECTRACK"
                        ],
                        "url": "http://www.securitytracker.com/id/1036431"
                    },
                    {
                        "name": "92036",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_BID"
                        ],
                        "url": "http://www.securityfocus.com/bid/92036"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://github.com/libarchive/libarchive/files/295073/libarchiveOverflow.txt"
                    },
                    {
                        "name": "[oss-security] 20160720 Buffer overflow in libarchive-3.2.0",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "http://www.openwall.com/lists/oss-security/2016/07/20/1"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://github.com/libarchive/libarchive/commit/3014e198"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1347085"
                    },
                    {
                        "name": "GLSA-201701-03",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_GENTOO"
                        ],
                        "url": "https://security.gentoo.org/glsa/201701-03"
                    },
                    {
                        "name": "[oss-security] 20160721 Re: Buffer overflow in libarchive-3.2.0",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "http://www.openwall.com/lists/oss-security/2016/07/21/3"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://github.com/libarchive/libarchive/issues/711"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2016-6250",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Integer overflow in the ISO9660 writer in libarchive before 3.2.1 allows remote attackers to cause a denial of service (application crash) or execute arbitrary code via vectors related to verifying filename lengths when writing an ISO9660 archive, which trigger a buffer overflow."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "RHSA-2016:1844",
                                "refsource": "REDHAT",
                                "url": "http://rhn.redhat.com/errata/RHSA-2016-1844.html"
                            },
                            {
                                "name": "http://www.oracle.com/technetwork/topics/security/linuxbulletinjul2016-3090544.html",
                                "refsource": "CONFIRM",
                                "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinjul2016-3090544.html"
                            },
                            {
                                "name": "1036431",
                                "refsource": "SECTRACK",
                                "url": "http://www.securitytracker.com/id/1036431"
                            },
                            {
                                "name": "92036",
                                "refsource": "BID",
                                "url": "http://www.securityfocus.com/bid/92036"
                            },
                            {
                                "name": "https://github.com/libarchive/libarchive/files/295073/libarchiveOverflow.txt",
                                "refsource": "MISC",
                                "url": "https://github.com/libarchive/libarchive/files/295073/libarchiveOverflow.txt"
                            },
                            {
                                "name": "[oss-security] 20160720 Buffer overflow in libarchive-3.2.0",
                                "refsource": "MLIST",
                                "url": "http://www.openwall.com/lists/oss-security/2016/07/20/1"
                            },
                            {
                                "name": "https://github.com/libarchive/libarchive/commit/3014e198",
                                "refsource": "CONFIRM",
                                "url": "https://github.com/libarchive/libarchive/commit/3014e198"
                            },
                            {
                                "name": "https://bugzilla.redhat.com/show_bug.cgi?id=1347085",
                                "refsource": "CONFIRM",
                                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1347085"
                            },
                            {
                                "name": "GLSA-201701-03",
                                "refsource": "GENTOO",
                                "url": "https://security.gentoo.org/glsa/201701-03"
                            },
                            {
                                "name": "[oss-security] 20160721 Re: Buffer overflow in libarchive-3.2.0",
                                "refsource": "MLIST",
                                "url": "http://www.openwall.com/lists/oss-security/2016/07/21/3"
                            },
                            {
                                "name": "https://github.com/libarchive/libarchive/issues/711",
                                "refsource": "CONFIRM",
                                "url": "https://github.com/libarchive/libarchive/issues/711"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2016-6250",
            "datePublished": "2016-09-21T14:00:00",
            "dateReserved": "2016-07-20T00:00:00",
            "dateUpdated": "2018-01-04T19:57:01",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "datePublic": "2016-10-10T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The IP stack in the Linux kernel through 4.8.2 allows remote attackers to cause a denial of service (stack consumption and panic) or possibly have unspecified other impact by triggering use of the GRO path for large crafted packets, as demonstrated by packets that contain only VLAN headers, a related issue to CVE-2016-8666."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2018-01-04T19:57:01",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "name": "RHSA-2016:2107",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "http://rhn.redhat.com/errata/RHSA-2016-2107.html"
                    },
                    {
                        "name": "RHSA-2017:0372",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "https://access.redhat.com/errata/RHSA-2017:0372"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://bto.bluecoat.com/security-advisory/sa134"
                    },
                    {
                        "name": "[oss-security] 20161010 CVE-2016-7039 Kernel: net: unbounded recursion in the vlan GRO processing",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "http://www.openwall.com/lists/oss-security/2016/10/10/15"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinoct2016-3090545.html"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1375944"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://patchwork.ozlabs.org/patch/680412/"
                    },
                    {
                        "name": "RHSA-2016:2047",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "http://rhn.redhat.com/errata/RHSA-2016-2047.html"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "http://www.oracle.com/technetwork/topics/security/ovmbulletinoct2016-3090547.html"
                    },
                    {
                        "name": "RHSA-2016:2110",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "http://rhn.redhat.com/errata/RHSA-2016-2110.html"
                    },
                    {
                        "name": "93476",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_BID"
                        ],
                        "url": "http://www.securityfocus.com/bid/93476"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2016-7039",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "The IP stack in the Linux kernel through 4.8.2 allows remote attackers to cause a denial of service (stack consumption and panic) or possibly have unspecified other impact by triggering use of the GRO path for large crafted packets, as demonstrated by packets that contain only VLAN headers, a related issue to CVE-2016-8666."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "RHSA-2016:2107",
                                "refsource": "REDHAT",
                                "url": "http://rhn.redhat.com/errata/RHSA-2016-2107.html"
                            },
                            {
                                "name": "RHSA-2017:0372",
                                "refsource": "REDHAT",
                                "url": "https://access.redhat.com/errata/RHSA-2017:0372"
                            },
                            {
                                "name": "https://bto.bluecoat.com/security-advisory/sa134",
                                "refsource": "CONFIRM",
                                "url": "https://bto.bluecoat.com/security-advisory/sa134"
                            },
                            {
                                "name": "[oss-security] 20161010 CVE-2016-7039 Kernel: net: unbounded recursion in the vlan GRO processing",
                                "refsource": "MLIST",
                                "url": "http://www.openwall.com/lists/oss-security/2016/10/10/15"
                            },
                            {
                                "name": "http://www.oracle.com/technetwork/topics/security/linuxbulletinoct2016-3090545.html",
                                "refsource": "CONFIRM",
                                "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinoct2016-3090545.html"
                            },
                            {
                                "name": "https://bugzilla.redhat.com/show_bug.cgi?id=1375944",
                                "refsource": "CONFIRM",
                                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1375944"
                            },
                            {
                                "name": "https://patchwork.ozlabs.org/patch/680412/",
                                "refsource": "CONFIRM",
                                "url": "https://patchwork.ozlabs.org/patch/680412/"
                            },
                            {
                                "name": "RHSA-2016:2047",
                                "refsource": "REDHAT",
                                "url": "http://rhn.redhat.com/errata/RHSA-2016-2047.html"
                            },
                            {
                                "name": "http://www.oracle.com/technetwork/topics/security/ovmbulletinoct2016-3090547.html",
                                "refsource": "CONFIRM",
                                "url": "http://www.oracle.com/technetwork/topics/security/ovmbulletinoct2016-3090547.html"
                            },
                            {
                                "name": "RHSA-2016:2110",
                                "refsource": "REDHAT",
                                "url": "http://rhn.redhat.com/errata/RHSA-2016-2110.html"
                            },
                            {
                                "name": "93476",
                                "refsource": "BID",
                                "url": "http://www.securityfocus.com/bid/93476"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2016-7039",
            "datePublished": "2016-10-16T21:00:00",
            "dateReserved": "2016-08-23T00:00:00",
            "dateUpdated": "2018-01-04T19:57:01",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "datePublic": "2016-02-19T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "libarchive before 3.2.0 does not limit the number of recursive decompressions, which allows remote attackers to cause a denial of service (memory consumption and application crash) via a crafted gzip file."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2017-06-30T16:57:01",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "name": "RHSA-2016:1844",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "http://rhn.redhat.com/errata/RHSA-2016-1844.html"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinjul2016-3090544.html"
                    },
                    {
                        "name": "[oss-security] 20160908 Re: CVE request: libarchive (pre 3.2.0) denial of service with gzip quine",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "http://www.openwall.com/lists/oss-security/2016/09/08/18"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://github.com/libarchive/libarchive/commit/6e06b1c89dd0d16f74894eac4cfc1327a06ee4a0"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://github.com/libarchive/libarchive/issues/660"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1347086"
                    },
                    {
                        "name": "RHSA-2016:1850",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "http://rhn.redhat.com/errata/RHSA-2016-1850.html"
                    },
                    {
                        "name": "[oss-security] 20160908 CVE request: libarchive (pre 3.2.0) denial of service with gzip quine",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "http://www.openwall.com/lists/oss-security/2016/09/08/15"
                    },
                    {
                        "name": "GLSA-201701-03",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_GENTOO"
                        ],
                        "url": "https://security.gentoo.org/glsa/201701-03"
                    },
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=207362"
                    },
                    {
                        "name": "92901",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_BID"
                        ],
                        "url": "http://www.securityfocus.com/bid/92901"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2016-7166",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "libarchive before 3.2.0 does not limit the number of recursive decompressions, which allows remote attackers to cause a denial of service (memory consumption and application crash) via a crafted gzip file."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "RHSA-2016:1844",
                                "refsource": "REDHAT",
                                "url": "http://rhn.redhat.com/errata/RHSA-2016-1844.html"
                            },
                            {
                                "name": "http://www.oracle.com/technetwork/topics/security/linuxbulletinjul2016-3090544.html",
                                "refsource": "CONFIRM",
                                "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinjul2016-3090544.html"
                            },
                            {
                                "name": "[oss-security] 20160908 Re: CVE request: libarchive (pre 3.2.0) denial of service with gzip quine",
                                "refsource": "MLIST",
                                "url": "http://www.openwall.com/lists/oss-security/2016/09/08/18"
                            },
                            {
                                "name": "https://github.com/libarchive/libarchive/commit/6e06b1c89dd0d16f74894eac4cfc1327a06ee4a0",
                                "refsource": "CONFIRM",
                                "url": "https://github.com/libarchive/libarchive/commit/6e06b1c89dd0d16f74894eac4cfc1327a06ee4a0"
                            },
                            {
                                "name": "https://github.com/libarchive/libarchive/issues/660",
                                "refsource": "CONFIRM",
                                "url": "https://github.com/libarchive/libarchive/issues/660"
                            },
                            {
                                "name": "https://bugzilla.redhat.com/show_bug.cgi?id=1347086",
                                "refsource": "CONFIRM",
                                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1347086"
                            },
                            {
                                "name": "RHSA-2016:1850",
                                "refsource": "REDHAT",
                                "url": "http://rhn.redhat.com/errata/RHSA-2016-1850.html"
                            },
                            {
                                "name": "[oss-security] 20160908 CVE request: libarchive (pre 3.2.0) denial of service with gzip quine",
                                "refsource": "MLIST",
                                "url": "http://www.openwall.com/lists/oss-security/2016/09/08/15"
                            },
                            {
                                "name": "GLSA-201701-03",
                                "refsource": "GENTOO",
                                "url": "https://security.gentoo.org/glsa/201701-03"
                            },
                            {
                                "name": "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=207362",
                                "refsource": "CONFIRM",
                                "url": "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=207362"
                            },
                            {
                                "name": "92901",
                                "refsource": "BID",
                                "url": "http://www.securityfocus.com/bid/92901"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2016-7166",
            "datePublished": "2016-09-21T14:00:00",
            "dateReserved": "2016-09-08T00:00:00",
            "dateUpdated": "2017-06-30T16:57:01",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "datePublic": "2018-09-26T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Qemu has a Buffer Overflow in pcnet_receive in hw/net/pcnet.c because an incorrect integer data type is used."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2019-09-24T15:06:17",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "name": "[oss-security] 20181008 Qemu: integer overflow issues",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "http://www.openwall.com/lists/oss-security/2018/10/08/1"
                    },
                    {
                        "name": "DSA-4338",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_DEBIAN"
                        ],
                        "url": "https://www.debian.org/security/2018/dsa-4338"
                    },
                    {
                        "name": "USN-3826-1",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/3826-1/"
                    },
                    {
                        "name": "[qemu-devel] 20180926 [PULL 23/25] pcnet: fix possible buffer overflow",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "https://lists.gnu.org/archive/html/qemu-devel/2018-09/msg03268.html"
                    },
                    {
                        "name": "[debian-lts-announce] 20181130 [SECURITY] [DLA 1599-1] qemu security update",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "https://lists.debian.org/debian-lts-announce/2018/11/msg00038.html"
                    },
                    {
                        "name": "RHSA-2019:2892",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ],
                        "url": "https://access.redhat.com/errata/RHSA-2019:2892"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2018-17962",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Qemu has a Buffer Overflow in pcnet_receive in hw/net/pcnet.c because an incorrect integer data type is used."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "[oss-security] 20181008 Qemu: integer overflow issues",
                                "refsource": "MLIST",
                                "url": "http://www.openwall.com/lists/oss-security/2018/10/08/1"
                            },
                            {
                                "name": "DSA-4338",
                                "refsource": "DEBIAN",
                                "url": "https://www.debian.org/security/2018/dsa-4338"
                            },
                            {
                                "name": "USN-3826-1",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/3826-1/"
                            },
                            {
                                "name": "[qemu-devel] 20180926 [PULL 23/25] pcnet: fix possible buffer overflow",
                                "refsource": "MLIST",
                                "url": "https://lists.gnu.org/archive/html/qemu-devel/2018-09/msg03268.html"
                            },
                            {
                                "name": "[debian-lts-announce] 20181130 [SECURITY] [DLA 1599-1] qemu security update",
                                "refsource": "MLIST",
                                "url": "https://lists.debian.org/debian-lts-announce/2018/11/msg00038.html"
                            },
                            {
                                "name": "RHSA-2019:2892",
                                "refsource": "REDHAT",
                                "url": "https://access.redhat.com/errata/RHSA-2019:2892"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2018-17962",
            "datePublished": "2018-10-09T22:00:00",
            "dateReserved": "2018-10-03T00:00:00",
            "dateUpdated": "2019-09-24T15:06:17",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2022-41862",
            "assignerOrgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
            "assignerShortName": "redhat",
            "dateUpdated": "2023-04-27T00:00:00",
            "dateReserved": "2022-09-30T00:00:00",
            "datePublished": "2023-03-03T00:00:00"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                    "shortName": "redhat",
                    "dateUpdated": "2023-04-27T00:00:00"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "In PostgreSQL, a modified, unauthenticated server can send an unterminated string during the establishment of Kerberos transport encryption. In certain conditions a server can cause a libpq client to over-read and report an error message containing uninitialized bytes."
                    }
                ],
                "affected": [
                    {
                        "vendor": "n/a",
                        "product": "postgresql",
                        "versions": [
                            {
                                "version": "postgresql 5.2, postgresql 14.7, postgresql 13.10, postgresql 12.14, postgresql 11.19",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.postgresql.org/support/security/CVE-2022-41862/"
                    },
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2165722"
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20230427-0002/"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "type": "CWE",
                                "lang": "en",
                                "description": "CWE-200",
                                "cweId": "CWE-200"
                            }
                        ]
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-5869",
            "assignerOrgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
            "state": "PUBLISHED",
            "assignerShortName": "redhat",
            "dateReserved": "2023-10-31T03:56:42.638Z",
            "datePublished": "2023-12-10T17:56:57.131Z",
            "dateUpdated": "2024-01-25T20:06:52.056Z"
        },
        "containers": {
            "cna": {
                "title": "Postgresql: buffer overrun from integer overflow in array modification",
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "value": "Important",
                                "namespace": "https://access.redhat.com/security/updates/classification/"
                            },
                            "type": "Red Hat severity rating"
                        }
                    },
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 8.8,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "LOW",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS"
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A flaw was found in PostgreSQL that allows authenticated database users to execute arbitrary code through missing overflow checks during SQL array value modification. This issue exists due to an integer overflow during array modification where a remote user can trigger the overflow by providing specially crafted data. This enables the execution of arbitrary code on the target system, allowing users to write arbitrary bytes to memory and extensively read the server's memory."
                    }
                ],
                "affected": [
                    {
                        "product": "PostgreSQL",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "version": "16.1",
                                "status": "unaffected"
                            },
                            {
                                "version": "15.5",
                                "status": "unaffected"
                            },
                            {
                                "version": "14.10",
                                "status": "unaffected"
                            },
                            {
                                "version": "13.13",
                                "status": "unaffected"
                            },
                            {
                                "version": "12.17",
                                "status": "unaffected"
                            },
                            {
                                "version": "11.22",
                                "status": "unaffected"
                            }
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-central-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-main-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-operator-bundle",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-slim-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:9.2.24-9.el7_9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/o:redhat:enterprise_linux:7::computenode",
                            "cpe:/o:redhat:enterprise_linux:7::client",
                            "cpe:/o:redhat:enterprise_linux:7::server",
                            "cpe:/o:redhat:enterprise_linux:7::workstation"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231114113712.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231128173330.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231201202407.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231114113548.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.1 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8010020231130170510.c27ad7f8",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.1::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Advanced Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231128165246.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Advanced Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231201202149.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231128165246.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231201202149.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231128165246.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231201202149.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Advanced Mission Critical Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127153301.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Advanced Mission Critical Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127154806.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Advanced Mission Critical Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127142440.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127153301.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127154806.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127142440.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127153301.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127154806.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127142440.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8060020231114115246.ad008a3a",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.6::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8060020231128165328.ad008a3a",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.6::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8060020231201202249.ad008a3a",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.6::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231114105206.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231128165335.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231201202316.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231113134015.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el9_3",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::crb",
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "9030020231120082734.rhel9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.0 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el9_0",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.0::appstream",
                            "cpe:/a:redhat:rhel_eus:9.0::crb"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.2 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el9_2",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.2::appstream",
                            "cpe:/a:redhat:rhel_eus:9.2::crb"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.2 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "9020020231115020618.rhel9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Software Collections for Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "rh-postgresql12-postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:12.17-1.el7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_software_collections:3::el7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Software Collections for Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "rh-postgresql10-postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:10.23-2.el7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_software_collections:3::el7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Software Collections for Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "rh-postgresql13-postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_software_collections:3::el7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-central-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-main-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-operator-bundle",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-slim-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-central-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-main-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-operator-bundle",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-slim-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 6",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "unknown",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:6"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:16/postgresql",
                        "defaultStatus": "affected",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:16/postgresql",
                        "defaultStatus": "affected",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:9"
                        ]
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "postgresql:13/postgresql",
                        "defaultStatus": "affected"
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "postgresql:12/postgresql",
                        "defaultStatus": "affected"
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "postgresql:15/postgresql",
                        "defaultStatus": "affected"
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected"
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "postgresql:14/postgresql",
                        "defaultStatus": "affected"
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "mingw-postgresql",
                        "defaultStatus": "affected"
                    }
                ],
                "references": [
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7545",
                        "name": "RHSA-2023:7545",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7579",
                        "name": "RHSA-2023:7579",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7580",
                        "name": "RHSA-2023:7580",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7581",
                        "name": "RHSA-2023:7581",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7616",
                        "name": "RHSA-2023:7616",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7656",
                        "name": "RHSA-2023:7656",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7666",
                        "name": "RHSA-2023:7666",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7667",
                        "name": "RHSA-2023:7667",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7694",
                        "name": "RHSA-2023:7694",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7695",
                        "name": "RHSA-2023:7695",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7714",
                        "name": "RHSA-2023:7714",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7770",
                        "name": "RHSA-2023:7770",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7771",
                        "name": "RHSA-2023:7771",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7772",
                        "name": "RHSA-2023:7772",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7778",
                        "name": "RHSA-2023:7778",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7783",
                        "name": "RHSA-2023:7783",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7784",
                        "name": "RHSA-2023:7784",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7785",
                        "name": "RHSA-2023:7785",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7786",
                        "name": "RHSA-2023:7786",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7788",
                        "name": "RHSA-2023:7788",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7789",
                        "name": "RHSA-2023:7789",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7790",
                        "name": "RHSA-2023:7790",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7878",
                        "name": "RHSA-2023:7878",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7883",
                        "name": "RHSA-2023:7883",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7884",
                        "name": "RHSA-2023:7884",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7885",
                        "name": "RHSA-2023:7885",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2024:0304",
                        "name": "RHSA-2024:0304",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2024:0332",
                        "name": "RHSA-2024:0332",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2024:0337",
                        "name": "RHSA-2024:0337",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/security/cve/CVE-2023-5869",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2247169",
                        "name": "RHBZ#2247169",
                        "tags": [
                            "issue-tracking",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20240119-0003/"
                    },
                    {
                        "url": "https://www.postgresql.org/about/news/postgresql-161-155-1410-1313-1217-and-1122-released-2749/"
                    },
                    {
                        "url": "https://www.postgresql.org/support/security/CVE-2023-5869/"
                    }
                ],
                "datePublic": "2023-11-09T00:00:00+00:00",
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-190",
                                "description": "Integer Overflow or Wraparound",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "x_redhatCweChain": "CWE-190: Integer Overflow or Wraparound",
                "workarounds": [
                    {
                        "lang": "en",
                        "value": "Red Hat has investigated whether a possible mitigation exists for this issue, and has not been able to identify a practical example. Please update the affected package as soon as possible."
                    }
                ],
                "timeline": [
                    {
                        "lang": "en",
                        "time": "2023-10-31T00:00:00+00:00",
                        "value": "Reported to Red Hat."
                    },
                    {
                        "lang": "en",
                        "time": "2023-11-09T00:00:00+00:00",
                        "value": "Made public."
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "value": "Upstream acknowledges Pedro Gallegos as the original reporter."
                    }
                ],
                "providerMetadata": {
                    "orgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                    "shortName": "redhat",
                    "dateUpdated": "2024-01-25T20:06:52.056Z"
                }
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-39417",
            "assignerOrgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
            "state": "PUBLISHED",
            "assignerShortName": "redhat",
            "dateReserved": "2023-08-01T09:31:02.842Z",
            "datePublished": "2023-08-11T12:19:15.108Z",
            "dateUpdated": "2024-01-25T08:51:33.578Z"
        },
        "containers": {
            "cna": {
                "title": "Postgresql: extension script @substitutions@ within quoting allow sql injection",
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "value": "Moderate",
                                "namespace": "https://access.redhat.com/security/updates/classification/"
                            },
                            "type": "Red Hat severity rating"
                        }
                    },
                    {
                        "cvssV3_1": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "LOW",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS"
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "IN THE EXTENSION SCRIPT, a SQL Injection vulnerability was found in PostgreSQL if it uses @extowner@, @extschema@, or @extschema:...@ inside a quoting construct (dollar quoting, '', or \"\"). If an administrator has installed files of a vulnerable, trusted, non-bundled extension, an attacker with database-level CREATE privilege can execute arbitrary code as the bootstrap superuser."
                    }
                ],
                "affected": [
                    {
                        "product": "postgresql",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "version": "11.21",
                                "status": "unaffected"
                            },
                            {
                                "version": "12.16",
                                "status": "unaffected"
                            },
                            {
                                "version": "13.12",
                                "status": "unaffected"
                            },
                            {
                                "version": "14.9",
                                "status": "unaffected"
                            },
                            {
                                "version": "15.4",
                                "status": "unaffected"
                            }
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-central-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-main-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-operator-bundle",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Advanced Cluster Security 4.2",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-slim-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.2.4-7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.2::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231114113712.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231128173330.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231114113548.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Advanced Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231128165246.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_aus:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231128165246.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_aus:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231128165246.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream",
                            "cpe:/a:redhat:rhel_aus:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Advanced Mission Critical Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127153301.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Advanced Mission Critical Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127154806.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127153301.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127154806.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127153301.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231127154806.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8060020231114115246.ad008a3a",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.6::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8060020231128165328.ad008a3a",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.6::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:13",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231114105206.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:12",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231128165335.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.8 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231113134015.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el9_3",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::crb",
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "9030020231120082734.rhel9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.0 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el9_0",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.0::appstream",
                            "cpe:/a:redhat:rhel_eus:9.0::crb"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.2 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el9_2",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.2::appstream",
                            "cpe:/a:redhat:rhel_eus:9.2::crb"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.2 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:15",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "9020020231115020618.rhel9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Software Collections for Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "rh-postgresql12-postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:12.17-1.el7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_software_collections:3::el7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Software Collections for Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "rh-postgresql13-postgresql",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "0:13.13-1.el7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_software_collections:3::el7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-central-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-main-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-operator-bundle",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-7",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-3.74-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-slim-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "3.74.8-9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:3.74::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-central-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-main-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-operator-bundle",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "RHACS-4.1-RHEL-8",
                        "collectionURL": "https://catalog.redhat.com/software/containers/",
                        "packageName": "advanced-cluster-security/rhacs-scanner-db-slim-rhel8",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "4.1.6-6",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:advanced_cluster_security:4.1::el8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 6",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "unknown",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:6"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql",
                        "defaultStatus": "unknown",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "postgresql:10/postgresql",
                        "defaultStatus": "affected",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:8"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Software Collections",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "rh-postgresql10-postgresql",
                        "defaultStatus": "affected",
                        "cpes": [
                            "cpe:/a:redhat:rhel_software_collections:3"
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7545",
                        "name": "RHSA-2023:7545",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7579",
                        "name": "RHSA-2023:7579",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7580",
                        "name": "RHSA-2023:7580",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7581",
                        "name": "RHSA-2023:7581",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7616",
                        "name": "RHSA-2023:7616",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7656",
                        "name": "RHSA-2023:7656",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7666",
                        "name": "RHSA-2023:7666",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7667",
                        "name": "RHSA-2023:7667",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7694",
                        "name": "RHSA-2023:7694",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7695",
                        "name": "RHSA-2023:7695",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7714",
                        "name": "RHSA-2023:7714",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7770",
                        "name": "RHSA-2023:7770",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7772",
                        "name": "RHSA-2023:7772",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7784",
                        "name": "RHSA-2023:7784",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7785",
                        "name": "RHSA-2023:7785",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7883",
                        "name": "RHSA-2023:7883",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7884",
                        "name": "RHSA-2023:7884",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7885",
                        "name": "RHSA-2023:7885",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2024:0304",
                        "name": "RHSA-2024:0304",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2024:0332",
                        "name": "RHSA-2024:0332",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2024:0337",
                        "name": "RHSA-2024:0337",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/security/cve/CVE-2023-39417",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2228111",
                        "name": "RHBZ#2228111",
                        "tags": [
                            "issue-tracking",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://lists.debian.org/debian-lts-announce/2023/10/msg00003.html"
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20230915-0002/"
                    },
                    {
                        "url": "https://www.debian.org/security/2023/dsa-5553"
                    },
                    {
                        "url": "https://www.debian.org/security/2023/dsa-5554"
                    },
                    {
                        "url": "https://www.postgresql.org/support/security/CVE-2023-39417"
                    }
                ],
                "datePublic": "2023-08-10T00:00:00+00:00",
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-89",
                                "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "x_redhatCweChain": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "timeline": [
                    {
                        "lang": "en",
                        "time": "2023-08-01T00:00:00+00:00",
                        "value": "Reported to Red Hat."
                    },
                    {
                        "lang": "en",
                        "time": "2023-08-10T00:00:00+00:00",
                        "value": "Made public."
                    }
                ],
                "providerMetadata": {
                    "orgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                    "shortName": "redhat",
                    "dateUpdated": "2024-01-25T08:51:33.578Z"
                }
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2024-0985",
            "assignerOrgId": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
            "state": "PUBLISHED",
            "assignerShortName": "PostgreSQL",
            "dateReserved": "2024-01-27T20:47:02.113Z",
            "datePublished": "2024-02-08T13:00:02.411Z",
            "dateUpdated": "2024-02-08T13:00:02.411Z"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
                    "shortName": "PostgreSQL",
                    "dateUpdated": "2024-02-08T13:00:02.411Z"
                },
                "title": "PostgreSQL non-owner REFRESH MATERIALIZED VIEW CONCURRENTLY executes arbitrary SQL",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Late privilege drop in REFRESH MATERIALIZED VIEW CONCURRENTLY in PostgreSQL allows an object creator to execute arbitrary SQL functions as the command issuer. The command intends to run SQL functions as the owner of the materialized view, enabling safe refresh of untrusted materialized views. The victim is a superuser or member of one of the attacker's roles. The attack requires luring the victim into running REFRESH MATERIALIZED VIEW CONCURRENTLY on the attacker's materialized view. As part of exploiting this vulnerability, the attacker creates functions that use CREATE RULE to convert the internally-built temporary table to a view. Versions before PostgreSQL 15.6, 14.11, 13.14, and 12.18 are affected. The only known exploit does not work in PostgreSQL 16 and later. For defense in depth, PostgreSQL 16.2 adds the protections that older branches are using to fix their vulnerability."
                    }
                ],
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "product": "PostgreSQL",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "lessThan": "15.6",
                                "status": "affected",
                                "version": "15",
                                "versionType": "rpm"
                            },
                            {
                                "lessThan": "14.11",
                                "status": "affected",
                                "version": "14",
                                "versionType": "rpm"
                            },
                            {
                                "lessThan": "13.14",
                                "status": "affected",
                                "version": "13",
                                "versionType": "rpm"
                            },
                            {
                                "lessThan": "12.18",
                                "status": "affected",
                                "version": "0",
                                "versionType": "rpm"
                            }
                        ]
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-271",
                                "type": "CWE",
                                "description": "Privilege Dropping / Lowering Errors"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.postgresql.org/support/security/CVE-2024-0985/"
                    },
                    {
                        "url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00017.html"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
                            "baseScore": 8,
                            "baseSeverity": "HIGH"
                        }
                    }
                ],
                "configurations": [
                    {
                        "lang": "en",
                        "value": "attacker has permission to create non-temporary objects in at least one schema"
                    }
                ],
                "workarounds": [
                    {
                        "lang": "en",
                        "value": "Use REFRESH MATERIALIZED VIEW without CONCURRENTLY."
                    },
                    {
                        "lang": "en",
                        "value": "In a new database connection, authenticate as the materialized view owner."
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "value": "The PostgreSQL project thanks Pedro Gallegos for reporting this problem."
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2024-24213",
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "dateUpdated": "2024-03-05T01:15:47.086202",
            "dateReserved": "2024-01-25T00:00:00",
            "datePublished": "2024-02-08T00:00:00"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre",
                    "dateUpdated": "2024-03-05T01:15:47.086202"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Supabase PostgreSQL v15.1 was discovered to contain a SQL injection vulnerability via the component /pg_meta/default/query. NOTE: the vendor's position is that this is an intended feature; also, it exists in the Supabase dashboard product, not the Supabase PostgreSQL product. Specifically, /pg_meta/default/query is for SQL queries that are entered in an intended UI by an authorized user. Nothing is injected."
                    }
                ],
                "tags": [
                    "disputed"
                ],
                "affected": [
                    {
                        "vendor": "n/a",
                        "product": "n/a",
                        "versions": [
                            {
                                "version": "n/a",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://app.flows.sh:8443/project/default%2C"
                    },
                    {
                        "url": "https://reference1.example.com/project/default/logs/explorer%2C"
                    },
                    {
                        "url": "https://postfixadmin.ballardini.com.ar:8443/project/default/logs/explorer."
                    },
                    {
                        "url": "https://github.com/940198871/Vulnerability-details/blob/main/CVE-2024-24213"
                    },
                    {
                        "url": "https://supabase.com/docs/guides/database/overview#the-sql-editor"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "type": "text",
                                "lang": "en",
                                "description": "n/a"
                            }
                        ]
                    }
                ]
            }
        }
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Moodle",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "Fixed in moodle 4.0.2, moodle 3.11.8, moodle 3.9.15"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A stored XSS and blind SSRF vulnerability was found in Moodle, occurs due to insufficient sanitization of user-supplied data in the SCORM track details. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website to steal potentially sensitive information, change appearance of the web page, can perform phishing and drive-by-download attacks."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-79",
                                "description": "CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-07-27T04:06:37",
                    "orgId": "92fb86c3-55a5-4fb5-9c3f-4757b9e96dc5",
                    "shortName": "fedora"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2106275"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://moodle.org/mod/forum/discuss.php?d=436458"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-71921"
                    },
                    {
                        "name": "FEDORA-2022-81ce74b2dd",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_FEDORA"
                        ],
                        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6MOKYVRNFNAODP2XSMGJ5CRDUZCZKAR3/"
                    },
                    {
                        "name": "FEDORA-2022-7e7ce7df2e",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_FEDORA"
                        ],
                        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MTKUSFPSYFINSQFSOHDQIDVE6FWBEU6V/"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "patrick@puiterwijk.org",
                        "ID": "CVE-2022-35651",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Moodle",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "Fixed in moodle 4.0.2, moodle 3.11.8, moodle 3.9.15"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "A stored XSS and blind SSRF vulnerability was found in Moodle, occurs due to insufficient sanitization of user-supplied data in the SCORM track details. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website to steal potentially sensitive information, change appearance of the web page, can perform phishing and drive-by-download attacks."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://bugzilla.redhat.com/show_bug.cgi?id=2106275",
                                "refsource": "MISC",
                                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2106275"
                            },
                            {
                                "name": "https://moodle.org/mod/forum/discuss.php?d=436458",
                                "refsource": "MISC",
                                "url": "https://moodle.org/mod/forum/discuss.php?d=436458"
                            },
                            {
                                "name": "http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-71921",
                                "refsource": "MISC",
                                "url": "http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-71921"
                            },
                            {
                                "name": "FEDORA-2022-81ce74b2dd",
                                "refsource": "FEDORA",
                                "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6MOKYVRNFNAODP2XSMGJ5CRDUZCZKAR3/"
                            },
                            {
                                "name": "FEDORA-2022-7e7ce7df2e",
                                "refsource": "FEDORA",
                                "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MTKUSFPSYFINSQFSOHDQIDVE6FWBEU6V/"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "92fb86c3-55a5-4fb5-9c3f-4757b9e96dc5",
            "assignerShortName": "fedora",
            "cveId": "CVE-2022-35651",
            "datePublished": "2022-07-25T15:30:22",
            "dateReserved": "2022-07-12T00:00:00",
            "dateUpdated": "2022-07-27T04:06:37",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Moodle",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "Fixed in moodle 4.0.2, moodle 3.11.8, moodle 3.9.15"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A reflected XSS issue was identified in the LTI module of Moodle. The vulnerability exists due to insufficient sanitization of user-supplied data in the LTI module. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website to steal potentially sensitive information, change appearance of the web page, can perform phishing and drive-by-download attacks. This vulnerability does not impact authenticated users."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-79",
                                "description": "CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-07-27T04:06:31",
                    "orgId": "92fb86c3-55a5-4fb5-9c3f-4757b9e96dc5",
                    "shortName": "fedora"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2106277"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://moodle.org/mod/forum/discuss.php?d=436460"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-72299"
                    },
                    {
                        "name": "FEDORA-2022-81ce74b2dd",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_FEDORA"
                        ],
                        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6MOKYVRNFNAODP2XSMGJ5CRDUZCZKAR3/"
                    },
                    {
                        "name": "FEDORA-2022-7e7ce7df2e",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_FEDORA"
                        ],
                        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MTKUSFPSYFINSQFSOHDQIDVE6FWBEU6V/"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "patrick@puiterwijk.org",
                        "ID": "CVE-2022-35653",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Moodle",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "Fixed in moodle 4.0.2, moodle 3.11.8, moodle 3.9.15"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "A reflected XSS issue was identified in the LTI module of Moodle. The vulnerability exists due to insufficient sanitization of user-supplied data in the LTI module. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website to steal potentially sensitive information, change appearance of the web page, can perform phishing and drive-by-download attacks. This vulnerability does not impact authenticated users."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://bugzilla.redhat.com/show_bug.cgi?id=2106277",
                                "refsource": "MISC",
                                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2106277"
                            },
                            {
                                "name": "https://moodle.org/mod/forum/discuss.php?d=436460",
                                "refsource": "MISC",
                                "url": "https://moodle.org/mod/forum/discuss.php?d=436460"
                            },
                            {
                                "name": "http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-72299",
                                "refsource": "MISC",
                                "url": "http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-72299"
                            },
                            {
                                "name": "FEDORA-2022-81ce74b2dd",
                                "refsource": "FEDORA",
                                "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6MOKYVRNFNAODP2XSMGJ5CRDUZCZKAR3/"
                            },
                            {
                                "name": "FEDORA-2022-7e7ce7df2e",
                                "refsource": "FEDORA",
                                "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MTKUSFPSYFINSQFSOHDQIDVE6FWBEU6V/"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "92fb86c3-55a5-4fb5-9c3f-4757b9e96dc5",
            "assignerShortName": "fedora",
            "cveId": "CVE-2022-35653",
            "datePublished": "2022-07-25T15:33:11",
            "dateReserved": "2022-07-12T00:00:00",
            "dateUpdated": "2022-07-27T04:06:31",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-46847",
            "assignerOrgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
            "state": "PUBLISHED",
            "assignerShortName": "redhat",
            "dateReserved": "2023-10-27T08:36:38.158Z",
            "datePublished": "2023-11-03T07:58:05.641Z",
            "dateUpdated": "2024-01-22T22:36:22.320Z"
        },
        "containers": {
            "cna": {
                "title": "Squid: denial of service in http digest authentication",
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "value": "Critical",
                                "namespace": "https://access.redhat.com/security/updates/classification/"
                            },
                            "type": "Red Hat severity rating"
                        }
                    },
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 8.6,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "LOW",
                            "integrityImpact": "LOW",
                            "privilegesRequired": "NONE",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS"
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Squid is vulnerable to a Denial of Service,  where a remote attacker can perform buffer overflow attack by writing up to 2 MB of arbitrary data to heap memory when Squid is configured to accept HTTP Digest Authentication."
                    }
                ],
                "affected": [
                    {
                        "product": "squid",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "version": "6.4",
                                "status": "unaffected"
                            }
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 6 Extended Lifecycle Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid34",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:3.4.14-15.el6_10.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/o:redhat:rhel_els:6"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 6 Extended Lifecycle Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:3.1.23-24.el6_10.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/o:redhat:rhel_els:6"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:3.5.20-17.el7_9.9",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/o:redhat:enterprise_linux:7::workstation",
                            "cpe:/o:redhat:enterprise_linux:7::server"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 7.6 Advanced Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:3.5.20-12.el7_6.2",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/o:redhat:rhel_aus:7.6::server"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 7.7 Advanced Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:3.5.20-13.el7_7.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/o:redhat:rhel_aus:7.7::server"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8080020231030214932.63b34585",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8090020231030224841.a75119d5",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:8::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.1 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8010020231101141358.c27ad7f8",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_e4s:8.1::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Advanced Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231101135052.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231101135052.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.2 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8020020231101135052.4cda2c84",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.2::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.2::appstream",
                            "cpe:/a:redhat:rhel_tus:8.2::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Advanced Mission Critical Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231101101624.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Telecommunications Update Service",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231101101624.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.4 Update Services for SAP Solutions",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8040020231101101624.522a0ee4",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_aus:8.4::appstream",
                            "cpe:/a:redhat:rhel_e4s:8.4::appstream",
                            "cpe:/a:redhat:rhel_tus:8.4::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid:4",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "8060020231031165747.ad008a3a",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:8.6::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:5.5-5.el9_2.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:5.5-6.el9_3.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.0 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:5.2-1.el9_0.3",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.0::appstream"
                        ]
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "squid",
                        "defaultStatus": "affected"
                    }
                ],
                "references": [
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6266",
                        "name": "RHSA-2023:6266",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6267",
                        "name": "RHSA-2023:6267",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6268",
                        "name": "RHSA-2023:6268",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6748",
                        "name": "RHSA-2023:6748",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6801",
                        "name": "RHSA-2023:6801",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6803",
                        "name": "RHSA-2023:6803",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6804",
                        "name": "RHSA-2023:6804",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6805",
                        "name": "RHSA-2023:6805",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6810",
                        "name": "RHSA-2023:6810",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6882",
                        "name": "RHSA-2023:6882",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6884",
                        "name": "RHSA-2023:6884",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7213",
                        "name": "RHSA-2023:7213",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7576",
                        "name": "RHSA-2023:7576",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:7578",
                        "name": "RHSA-2023:7578",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/security/cve/CVE-2023-46847",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2245916",
                        "name": "RHBZ#2245916",
                        "tags": [
                            "issue-tracking",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://github.com/squid-cache/squid/security/advisories/GHSA-phqj-m8gv-cq4g"
                    },
                    {
                        "url": "https://lists.debian.org/debian-lts-announce/2024/01/msg00003.html"
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20231130-0002/"
                    }
                ],
                "datePublic": "2023-10-19T00:00:00+00:00",
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-120",
                                "description": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "x_redhatCweChain": "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                "timeline": [
                    {
                        "lang": "en",
                        "time": "2023-10-24T00:00:00+00:00",
                        "value": "Reported to Red Hat."
                    },
                    {
                        "lang": "en",
                        "time": "2023-10-19T00:00:00+00:00",
                        "value": "Made public."
                    }
                ],
                "providerMetadata": {
                    "orgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                    "shortName": "redhat",
                    "dateUpdated": "2024-01-22T22:36:22.320Z"
                }
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-46848",
            "assignerOrgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
            "state": "PUBLISHED",
            "assignerShortName": "redhat",
            "dateReserved": "2023-10-27T08:36:38.158Z",
            "datePublished": "2023-11-03T07:58:05.613Z",
            "dateUpdated": "2024-01-23T02:16:58.257Z"
        },
        "containers": {
            "cna": {
                "title": "Squid: denial of service in ftp",
                "metrics": [
                    {
                        "other": {
                            "content": {
                                "value": "Important",
                                "namespace": "https://access.redhat.com/security/updates/classification/"
                            },
                            "type": "Red Hat severity rating"
                        }
                    },
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 8.6,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "NONE",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "NONE",
                            "scope": "CHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS"
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Squid is vulnerable to Denial of Service,  where a remote attacker can perform DoS by sending ftp:// URLs in HTTP Request messages or constructing ftp:// URLs from FTP Native input."
                    }
                ],
                "affected": [
                    {
                        "product": "squid",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "version": "6.4",
                                "status": "unaffected"
                            }
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:5.5-5.el9_2.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:5.5-6.el9_3.1",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:enterprise_linux:9::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 9.0 Extended Update Support",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "affected",
                        "versions": [
                            {
                                "version": "7:5.2-1.el9_0.3",
                                "lessThan": "*",
                                "versionType": "rpm",
                                "status": "unaffected"
                            }
                        ],
                        "cpe": [
                            "cpe:/a:redhat:rhel_eus:9.0::appstream"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 6",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "unaffected",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:6"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 7",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "unaffected",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:7"
                        ]
                    },
                    {
                        "vendor": "Red Hat",
                        "product": "Red Hat Enterprise Linux 8",
                        "collectionURL": "https://access.redhat.com/downloads/content/package-browser/",
                        "packageName": "squid",
                        "defaultStatus": "unaffected",
                        "cpes": [
                            "cpe:/o:redhat:enterprise_linux:8"
                        ]
                    },
                    {
                        "product": "Fedora",
                        "vendor": "Fedora",
                        "collectionURL": "https://packages.fedoraproject.org/",
                        "packageName": "squid",
                        "defaultStatus": "affected"
                    }
                ],
                "references": [
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6266",
                        "name": "RHSA-2023:6266",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6268",
                        "name": "RHSA-2023:6268",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/errata/RHSA-2023:6748",
                        "name": "RHSA-2023:6748",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://access.redhat.com/security/cve/CVE-2023-46848",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2245919",
                        "name": "RHBZ#2245919",
                        "tags": [
                            "issue-tracking",
                            "x_refsource_REDHAT"
                        ]
                    },
                    {
                        "url": "https://github.com/squid-cache/squid/security/advisories/GHSA-2g3c-pg7q-g59w"
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20231214-0005/"
                    }
                ],
                "datePublic": "2023-10-19T00:00:00+00:00",
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-681",
                                "description": "Incorrect Conversion between Numeric Types",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "x_redhatCweChain": "CWE-400->CWE-681: Uncontrolled Resource Consumption leads to Incorrect Conversion between Numeric Types",
                "timeline": [
                    {
                        "lang": "en",
                        "time": "2023-10-24T00:00:00+00:00",
                        "value": "Reported to Red Hat."
                    },
                    {
                        "lang": "en",
                        "time": "2023-10-19T00:00:00+00:00",
                        "value": "Made public."
                    }
                ],
                "providerMetadata": {
                    "orgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                    "shortName": "redhat",
                    "dateUpdated": "2024-01-23T02:16:58.257Z"
                }
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2023-51767",
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "dateUpdated": "2024-01-25T14:06:38.770250",
            "dateReserved": "2023-12-24T00:00:00",
            "datePublished": "2023-12-24T00:00:00"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre",
                    "dateUpdated": "2024-01-25T14:06:38.770250"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "OpenSSH through 9.6, when common types of DRAM are used, might allow row hammer attacks (for authentication bypass) because the integer value of authenticated in mm_answer_authpassword does not resist flips of a single bit. NOTE: this is applicable to a certain threat model of attacker-victim co-location in which the attacker has user privileges."
                    }
                ],
                "affected": [
                    {
                        "vendor": "n/a",
                        "product": "n/a",
                        "versions": [
                            {
                                "version": "n/a",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://arxiv.org/abs/2309.02545"
                    },
                    {
                        "url": "https://github.com/openssh/openssh-portable/blob/8241b9c0529228b4b86d88b1a6076fb9f97e4a99/monitor.c#L878"
                    },
                    {
                        "url": "https://github.com/openssh/openssh-portable/blob/8241b9c0529228b4b86d88b1a6076fb9f97e4a99/auth-passwd.c#L77"
                    },
                    {
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2255850"
                    },
                    {
                        "url": "https://access.redhat.com/security/cve/CVE-2023-51767"
                    },
                    {
                        "url": "https://ubuntu.com/security/CVE-2023-51767"
                    },
                    {
                        "url": "https://security.netapp.com/advisory/ntap-20240125-0006/"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "type": "text",
                                "lang": "en",
                                "description": "n/a"
                            }
                        ]
                    }
                ]
            }
        }
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "n/a",
                        "vendor": "n/a",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "n/a"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The logrotation script (/etc/cron.daily/upstart) in the Ubuntu Upstart package before 1.13.2-0ubuntu9, as used in Ubuntu Vivid 15.04, allows local users to execute arbitrary commands and gain privileges via a crafted file in /run/user/*/upstart/sessions/."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "n/a",
                                "lang": "en",
                                "type": "text"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-10-03T16:16:11",
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_CONFIRM"
                        ],
                        "url": "https://bugs.launchpad.net/ubuntu/+source/upstart/+bug/1425685"
                    },
                    {
                        "name": "20150302 upstart logrotate privilege escalation in Ubuntu Vivid (development)",
                        "tags": [
                            "mailing-list",
                            "x_refsource_FULLDISC"
                        ],
                        "url": "http://seclists.org/fulldisclosure/2015/Mar/7"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "http://www.halfdog.net/Security/2015/UpstartLogrotationPrivilegeEscalation/"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "http://packetstormsecurity.com/files/130587/Ubuntu-Vivid-Upstart-Privilege-Escalation.html"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "cve@mitre.org",
                        "ID": "CVE-2015-2285",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "n/a",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "n/a"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "n/a"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "The logrotation script (/etc/cron.daily/upstart) in the Ubuntu Upstart package before 1.13.2-0ubuntu9, as used in Ubuntu Vivid 15.04, allows local users to execute arbitrary commands and gain privileges via a crafted file in /run/user/*/upstart/sessions/."
                            }
                        ]
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "n/a"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "https://bugs.launchpad.net/ubuntu/+source/upstart/+bug/1425685",
                                "refsource": "CONFIRM",
                                "url": "https://bugs.launchpad.net/ubuntu/+source/upstart/+bug/1425685"
                            },
                            {
                                "name": "20150302 upstart logrotate privilege escalation in Ubuntu Vivid (development)",
                                "refsource": "FULLDISC",
                                "url": "http://seclists.org/fulldisclosure/2015/Mar/7"
                            },
                            {
                                "name": "http://www.halfdog.net/Security/2015/UpstartLogrotationPrivilegeEscalation/",
                                "refsource": "MISC",
                                "url": "http://www.halfdog.net/Security/2015/UpstartLogrotationPrivilegeEscalation/"
                            },
                            {
                                "name": "http://packetstormsecurity.com/files/130587/Ubuntu-Vivid-Upstart-Privilege-Escalation.html",
                                "refsource": "MISC",
                                "url": "http://packetstormsecurity.com/files/130587/Ubuntu-Vivid-Upstart-Privilege-Escalation.html"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "cveId": "CVE-2015-2285",
            "datePublished": "2022-10-03T16:16:11",
            "dateReserved": "2022-10-03T00:00:00",
            "dateUpdated": "2022-10-03T16:16:11",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Dovecot",
                        "vendor": "The Dovecot Project",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "2.2.33.2"
                            }
                        ]
                    }
                ],
                "datePublic": "2018-02-28T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A specially crafted email delivered over SMTP and passed on to Dovecot by MTA can trigger an out of bounds read resulting in potential sensitive information disclosure and denial of service. In order to trigger this vulnerability, an attacker needs to send a specially crafted email message to the server."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_0": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 5.9,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "LOW",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "LOW",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:H",
                            "version": "3.0"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-125",
                                "description": "CWE-125: Out-of-bounds Read",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2022-04-19T18:21:09",
                    "orgId": "b86d76f8-0f8a-4a96-a78d-d8abfc7fc29b",
                    "shortName": "talos"
                },
                "references": [
                    {
                        "name": "USN-3587-1",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/3587-1/"
                    },
                    {
                        "name": "[debian-lts-announce] 20180331 [SECURITY] [DLA 1333-1] dovecot security update",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "https://lists.debian.org/debian-lts-announce/2018/03/msg00036.html"
                    },
                    {
                        "name": "DSA-4130",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_DEBIAN"
                        ],
                        "url": "https://www.debian.org/security/2018/dsa-4130"
                    },
                    {
                        "name": "USN-3587-2",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/3587-2/"
                    },
                    {
                        "name": "103201",
                        "tags": [
                            "vdb-entry",
                            "x_refsource_BID"
                        ],
                        "url": "http://www.securityfocus.com/bid/103201"
                    },
                    {
                        "name": "[dovecot-news] 20180228 v2.2.34 released",
                        "tags": [
                            "mailing-list",
                            "x_refsource_MLIST"
                        ],
                        "url": "https://www.dovecot.org/list/dovecot-news/2018-February/000370.html"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://talosintelligence.com/vulnerability_reports/TALOS-2017-0510"
                    }
                ],
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "ASSIGNER": "talos-cna@cisco.com",
                        "DATE_PUBLIC": "2018-02-28T00:00:00",
                        "ID": "CVE-2017-14461",
                        "STATE": "PUBLIC"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Dovecot",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "2.2.33.2"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "The Dovecot Project"
                                }
                            ]
                        }
                    },
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "A specially crafted email delivered over SMTP and passed on to Dovecot by MTA can trigger an out of bounds read resulting in potential sensitive information disclosure and denial of service. In order to trigger this vulnerability, an attacker needs to send a specially crafted email message to the server."
                            }
                        ]
                    },
                    "impact": {
                        "cvss": {
                            "baseScore": 5.9,
                            "baseSeverity": "Medium",
                            "vectorString": "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:H",
                            "version": "3.0"
                        }
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-125: Out-of-bounds Read"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "USN-3587-1",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/3587-1/"
                            },
                            {
                                "name": "[debian-lts-announce] 20180331 [SECURITY] [DLA 1333-1] dovecot security update",
                                "refsource": "MLIST",
                                "url": "https://lists.debian.org/debian-lts-announce/2018/03/msg00036.html"
                            },
                            {
                                "name": "DSA-4130",
                                "refsource": "DEBIAN",
                                "url": "https://www.debian.org/security/2018/dsa-4130"
                            },
                            {
                                "name": "USN-3587-2",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/3587-2/"
                            },
                            {
                                "name": "103201",
                                "refsource": "BID",
                                "url": "http://www.securityfocus.com/bid/103201"
                            },
                            {
                                "name": "[dovecot-news] 20180228 v2.2.34 released",
                                "refsource": "MLIST",
                                "url": "https://www.dovecot.org/list/dovecot-news/2018-February/000370.html"
                            },
                            {
                                "name": "https://talosintelligence.com/vulnerability_reports/TALOS-2017-0510",
                                "refsource": "MISC",
                                "url": "https://talosintelligence.com/vulnerability_reports/TALOS-2017-0510"
                            }
                        ]
                    }
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "b86d76f8-0f8a-4a96-a78d-d8abfc7fc29b",
            "assignerShortName": "talos",
            "cveId": "CVE-2017-14461",
            "datePublished": "2018-02-28T00:00:00",
            "dateReserved": "2017-09-13T00:00:00",
            "dateUpdated": "2022-04-19T18:21:09",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Python-apt",
                        "vendor": "Canonical",
                        "versions": [
                            {
                                "lessThan": "0.8.3ubuntu7.5",
                                "status": "affected",
                                "version": "0.8.3",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "0.9.3.5ubuntu3+esm2",
                                "status": "affected",
                                "version": "0.9.3.5",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.1.0~beta1ubuntu0.16.04.7",
                                "status": "affected",
                                "version": "1.1.0",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.6.5ubuntu0.1",
                                "status": "affected",
                                "version": "1.6.5",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.9.0ubuntu1.2",
                                "status": "affected",
                                "version": "1.9.0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "value": "Julian Andres Klode"
                    }
                ],
                "datePublic": "2019-08-06T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "python-apt only checks the MD5 sums of downloaded files in `Version.fetch_binary()` and `Version.fetch_source()` of apt/package.py in version 1.9.0ubuntu1 and earlier. This allows a man-in-the-middle attack which could potentially be used to install altered packages and has been fixed in versions 1.9.0ubuntu1.2, 1.6.5ubuntu0.1, 1.1.0~beta1ubuntu0.16.04.7, 0.9.3.5ubuntu3+esm2, and 0.8.3ubuntu7.5."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "NONE",
                            "baseScore": 4.7,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "LOW",
                            "integrityImpact": "LOW",
                            "privilegesRequired": "NONE",
                            "scope": "CHANGED",
                            "userInteraction": "REQUIRED",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            "version": "3.1"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-327",
                                "description": "CWE-327 Use of a Broken or Risky Cryptographic Algorithm",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2020-03-26T13:00:21",
                    "orgId": "cc1ad9ee-3454-478d-9317-d3e869d708bc",
                    "shortName": "canonical"
                },
                "references": [
                    {
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/4247-1/"
                    },
                    {
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/4247-3/"
                    }
                ],
                "source": {
                    "advisory": "https://usn.ubuntu.com/usn/usn-4247-1",
                    "defect": [
                        "https://bugs.launchpad.net/ubuntu/%2Bsource/python-apt/%2Bbug/1858972"
                    ],
                    "discovery": "UNKNOWN"
                },
                "title": "python-apt uses MD5 for validation",
                "x_generator": {
                    "engine": "Vulnogram 0.0.9"
                },
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "AKA": "",
                        "ASSIGNER": "security@ubuntu.com",
                        "DATE_PUBLIC": "2019-08-06T16:33:00.000Z",
                        "ID": "CVE-2019-15795",
                        "STATE": "PUBLIC",
                        "TITLE": "python-apt uses MD5 for validation"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Python-apt",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "0.8.3",
                                                            "version_value": "0.8.3ubuntu7.5"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "0.9.3.5",
                                                            "version_value": "0.9.3.5ubuntu3+esm2"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.1.0",
                                                            "version_value": "1.1.0~beta1ubuntu0.16.04.7"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.6.5",
                                                            "version_value": "1.6.5ubuntu0.1"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.9.0",
                                                            "version_value": "1.9.0ubuntu1.2"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "Canonical"
                                }
                            ]
                        }
                    },
                    "configuration": [],
                    "credit": [
                        {
                            "lang": "eng",
                            "value": "Julian Andres Klode"
                        }
                    ],
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "python-apt only checks the MD5 sums of downloaded files in `Version.fetch_binary()` and `Version.fetch_source()` of apt/package.py in version 1.9.0ubuntu1 and earlier. This allows a man-in-the-middle attack which could potentially be used to install altered packages and has been fixed in versions 1.9.0ubuntu1.2, 1.6.5ubuntu0.1, 1.1.0~beta1ubuntu0.16.04.7, 0.9.3.5ubuntu3+esm2, and 0.8.3ubuntu7.5."
                            }
                        ]
                    },
                    "exploit": [],
                    "generator": {
                        "engine": "Vulnogram 0.0.9"
                    },
                    "impact": {
                        "cvss": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "NONE",
                            "baseScore": 4.7,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "LOW",
                            "integrityImpact": "LOW",
                            "privilegesRequired": "NONE",
                            "scope": "CHANGED",
                            "userInteraction": "REQUIRED",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            "version": "3.1"
                        }
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-327 Use of a Broken or Risky Cryptographic Algorithm"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/4247-1/"
                            },
                            {
                                "name": "",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/4247-3/"
                            }
                        ]
                    },
                    "solution": [],
                    "source": {
                        "advisory": "https://usn.ubuntu.com/usn/usn-4247-1",
                        "defect": [
                            "https://bugs.launchpad.net/ubuntu/%2Bsource/python-apt/%2Bbug/1858972"
                        ],
                        "discovery": "UNKNOWN"
                    },
                    "work_around": []
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "cc1ad9ee-3454-478d-9317-d3e869d708bc",
            "assignerShortName": "canonical",
            "cveId": "CVE-2019-15795",
            "datePublished": "2019-08-06T00:00:00",
            "dateReserved": "2019-08-29T00:00:00",
            "dateUpdated": "2020-03-26T13:00:21",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "Python-apt",
                        "vendor": "Canonical",
                        "versions": [
                            {
                                "lessThan": "0.8.3ubuntu7.5",
                                "status": "affected",
                                "version": "0.8.3",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "0.9.3.5ubuntu3+esm2",
                                "status": "affected",
                                "version": "0.9.3.5",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.1.0~beta1ubuntu0.16.04.7",
                                "status": "affected",
                                "version": "1.1.0",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.6.5ubuntu0.1",
                                "status": "affected",
                                "version": "1.6.5",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.9.0ubuntu1.2",
                                "status": "affected",
                                "version": "1.9.0",
                                "versionType": "custom"
                            },
                            {
                                "lessThan": "1.9.5",
                                "status": "affected",
                                "version": "1.9.5",
                                "versionType": "custom"
                            }
                        ]
                    }
                ],
                "credits": [
                    {
                        "lang": "en",
                        "value": "Julian Andres Klode"
                    }
                ],
                "datePublic": "2019-12-12T00:00:00",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Python-apt doesn't check if hashes are signed in `Version.fetch_binary()` and `Version.fetch_source()` of apt/package.py or in `_fetch_archives()` of apt/cache.py in version 1.9.3ubuntu2 and earlier. This allows downloads from unsigned repositories which shouldn't be allowed and has been fixed in verisions 1.9.5, 1.9.0ubuntu1.2, 1.6.5ubuntu0.1, 1.1.0~beta1ubuntu0.16.04.7, 0.9.3.5ubuntu3+esm2, and 0.8.3ubuntu7.5."
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "NONE",
                            "baseScore": 4.7,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "LOW",
                            "integrityImpact": "LOW",
                            "privilegesRequired": "NONE",
                            "scope": "CHANGED",
                            "userInteraction": "REQUIRED",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            "version": "3.1"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-287",
                                "description": "CWE-287 Improper Authentication",
                                "lang": "en",
                                "type": "CWE"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "dateUpdated": "2020-03-26T13:00:21",
                    "orgId": "cc1ad9ee-3454-478d-9317-d3e869d708bc",
                    "shortName": "canonical"
                },
                "references": [
                    {
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/4247-1/"
                    },
                    {
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_UBUNTU"
                        ],
                        "url": "https://usn.ubuntu.com/4247-3/"
                    }
                ],
                "source": {
                    "advisory": "https://usn.ubuntu.com/4247-1/",
                    "defect": [
                        "https://bugs.launchpad.net/bugs/1858973"
                    ],
                    "discovery": "UNKNOWN"
                },
                "title": "python-apt downloads from untrusted sources",
                "x_generator": {
                    "engine": "Vulnogram 0.0.9"
                },
                "x_legacyV4Record": {
                    "CVE_data_meta": {
                        "AKA": "",
                        "ASSIGNER": "security@ubuntu.com",
                        "DATE_PUBLIC": "2019-12-12T17:47:00.000Z",
                        "ID": "CVE-2019-15796",
                        "STATE": "PUBLIC",
                        "TITLE": "python-apt downloads from untrusted sources"
                    },
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "Python-apt",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "0.8.3",
                                                            "version_value": "0.8.3ubuntu7.5"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "0.9.3.5",
                                                            "version_value": "0.9.3.5ubuntu3+esm2"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.1.0",
                                                            "version_value": "1.1.0~beta1ubuntu0.16.04.7"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.6.5",
                                                            "version_value": "1.6.5ubuntu0.1"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.9.0",
                                                            "version_value": "1.9.0ubuntu1.2"
                                                        },
                                                        {
                                                            "platform": "",
                                                            "version_affected": "<",
                                                            "version_name": "1.9.5",
                                                            "version_value": "1.9.5"
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                    "vendor_name": "Canonical"
                                }
                            ]
                        }
                    },
                    "configuration": [],
                    "credit": [
                        {
                            "lang": "eng",
                            "value": "Julian Andres Klode"
                        }
                    ],
                    "data_format": "MITRE",
                    "data_type": "CVE",
                    "data_version": "4.0",
                    "description": {
                        "description_data": [
                            {
                                "lang": "eng",
                                "value": "Python-apt doesn't check if hashes are signed in `Version.fetch_binary()` and `Version.fetch_source()` of apt/package.py or in `_fetch_archives()` of apt/cache.py in version 1.9.3ubuntu2 and earlier. This allows downloads from unsigned repositories which shouldn't be allowed and has been fixed in verisions 1.9.5, 1.9.0ubuntu1.2, 1.6.5ubuntu0.1, 1.1.0~beta1ubuntu0.16.04.7, 0.9.3.5ubuntu3+esm2, and 0.8.3ubuntu7.5."
                            }
                        ]
                    },
                    "exploit": [],
                    "generator": {
                        "engine": "Vulnogram 0.0.9"
                    },
                    "impact": {
                        "cvss": {
                            "attackComplexity": "HIGH",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "NONE",
                            "baseScore": 4.7,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "LOW",
                            "integrityImpact": "LOW",
                            "privilegesRequired": "NONE",
                            "scope": "CHANGED",
                            "userInteraction": "REQUIRED",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            "version": "3.1"
                        }
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "eng",
                                        "value": "CWE-287 Improper Authentication"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "name": "",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/4247-1/"
                            },
                            {
                                "name": "",
                                "refsource": "UBUNTU",
                                "url": "https://usn.ubuntu.com/4247-3/"
                            }
                        ]
                    },
                    "solution": [],
                    "source": {
                        "advisory": "https://usn.ubuntu.com/4247-1/",
                        "defect": [
                            "https://bugs.launchpad.net/bugs/1858973"
                        ],
                        "discovery": "UNKNOWN"
                    },
                    "work_around": []
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "cc1ad9ee-3454-478d-9317-d3e869d708bc",
            "assignerShortName": "canonical",
            "cveId": "CVE-2019-15796",
            "datePublished": "2019-12-12T00:00:00",
            "dateReserved": "2019-08-29T00:00:00",
            "dateUpdated": "2020-03-26T13:00:21",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2022-35744",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "state": "PUBLISHED",
            "assignerShortName": "microsoft",
            "dateReserved": "2022-07-13T18:19:42.613Z",
            "datePublished": "2023-05-31T18:07:00.959Z",
            "dateUpdated": "2023-12-20T21:27:37.775Z"
        },
        "containers": {
            "cna": {
                "title": "Windows Point-to-Point Protocol (PPP) Remote Code Execution Vulnerability",
                "datePublic": "2022-08-09T07:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3287:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3287:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3287:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3287",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3287:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3287",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3287:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3287",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1889:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1889:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1889:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.1889",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.887:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.1889:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.1889:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.1889",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_20H2:10.0.19042.1889:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.1889",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.856:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.856:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.856",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1889:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1889:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1889:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.1889",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19387:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19387:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19387",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5291:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5291:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5291",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5291:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5291",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5291:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5291",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26065:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26065",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26065:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26065",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20520:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20520:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20520:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20520",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21616:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21616",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21616:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21616:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21616",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21616:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21616",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26065:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26065",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26065:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26065",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23817:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23817",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23817:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23817",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20520:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20520",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20520:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20520",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Point-to-Point Protocol (PPP) Remote Code Execution Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Remote Code Execution",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-20T21:27:37.775Z"
                },
                "references": [
                    {
                        "name": "Windows Point-to-Point Protocol (PPP) Remote Code Execution Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-35744"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "CRITICAL",
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2022-41109",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "dateUpdated": "2024-01-18T16:55:27.586Z",
            "dateReserved": "2022-09-19T00:00:00",
            "datePublished": "2022-11-09T00:00:00"
        },
        "containers": {
            "cna": {
                "title": "Windows Win32k Elevation of Privilege Vulnerability",
                "datePublic": "2022-11-08T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3650:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3650:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3650:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3650",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3650:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3650",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3650:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3650",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2251:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2251:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2251:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1249:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1251:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1249",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2251:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2251:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1219:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1219:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.1219",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2251:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2251:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2251:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.819:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.819:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.819",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2251:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2251:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2251:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19567:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19567:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19567",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5501:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5501:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5501",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5501:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5501",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5501:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5501",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26221:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26221:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20671:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20670:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20671:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20670:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20670:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20671",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20670",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21768:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21768",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21768:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21768:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21768",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21768:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21768",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26221:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26221:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23968:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23968",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23968:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23968",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20671:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20670:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20671",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20670",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20671:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20670:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20671",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20670",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Win32k Elevation of Privilege Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Elevation of Privilege",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-01-18T16:55:27.586Z"
                },
                "references": [
                    {
                        "name": "Windows Win32k Elevation of Privilege Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41109"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2022-41118",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "dateUpdated": "2024-01-18T16:55:30.921Z",
            "dateReserved": "2022-09-19T00:00:00",
            "datePublished": "2022-11-09T00:00:00"
        },
        "containers": {
            "cna": {
                "title": "Windows Scripting Languages Remote Code Execution Vulnerability",
                "datePublic": "2022-11-08T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.819:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.819:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.819",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2251:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2251:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2251:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2251:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2251:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2251:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1249:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1251:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1249",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2251:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2251:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2251:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1219:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1219:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.1219",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3650:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3650:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3650:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3650",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2251:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2251:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.2251",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5501:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5501",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26221:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5501:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5501:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5501",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20671:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20670:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20671:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20671:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20670:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20671",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20670",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26221:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3650:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3650",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19567:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19567:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19567",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26221:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26221",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20671:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20670:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20671",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20670",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Scripting Languages Remote Code Execution Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Remote Code Execution",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-01-18T16:55:30.921Z"
                },
                "references": [
                    {
                        "name": "Windows Scripting Languages Remote Code Execution Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41118"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2023-21557",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "dateUpdated": "2023-12-14T18:02:33.187Z",
            "dateReserved": "2022-12-01T00:00:00",
            "datePublished": "2023-01-10T00:00:00"
        },
        "containers": {
            "cna": {
                "title": "Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability",
                "datePublic": "2023-01-10T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3887:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3887:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3887:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3887:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3887:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1487:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1487",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2486:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2486:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.2486",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1455:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1455:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.1455",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2486:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2486:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2486:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.2486",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.1105:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.1105:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.1105",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2486:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2486:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2486:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.2486",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19685:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19685:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19685",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5648:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5648:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5648",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5648:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5648",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5648:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5648",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26321:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26321",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26321:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26321",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20778:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20778:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20778:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20778",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21872",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21872",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21872",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26321:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26321",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24075:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24075",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24075:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24075",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20778:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20778",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20778:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20778",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Denial of Service",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-14T18:02:33.187Z"
                },
                "references": [
                    {
                        "name": "Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21557"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2023-21732",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "dateUpdated": "2023-12-14T18:02:43.475Z",
            "dateReserved": "2022-12-13T00:00:00",
            "datePublished": "2023-01-10T00:00:00"
        },
        "containers": {
            "cna": {
                "title": "Microsoft ODBC Driver Remote Code Execution Vulnerability",
                "datePublic": "2023-01-10T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3887:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3887:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3887:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3887:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3887:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3887",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1487:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1487",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2486:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2486:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.2486",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1455:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1455:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.1455",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2486:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2486:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2486:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.2486",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.1105:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.1105:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.1105",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2486:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2486:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2486:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.2486",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19685:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19685:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19685",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5648:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5648:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5648",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5648:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5648",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5648:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5648",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26321:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26321",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26321:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26321",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20778:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20778:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20778:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20778",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21872",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21872",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21872:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21872",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26321:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26321",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24075:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24075",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24075:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24075",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20778:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20778",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20778:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20778",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Microsoft ODBC Driver Remote Code Execution Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Remote Code Execution",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-14T18:02:43.475Z"
                },
                "references": [
                    {
                        "name": "Microsoft ODBC Driver Remote Code Execution Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21732"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 8.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2023-34367",
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "dateUpdated": "2023-06-14T00:00:00",
            "dateReserved": "2023-06-02T00:00:00",
            "datePublished": "2023-06-14T00:00:00"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                    "shortName": "mitre",
                    "dateUpdated": "2023-06-14T00:00:00"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Windows 7 is vulnerable to a full blind TCP/IP hijacking attack. The vulnerability exists in Windows 7 (any Windows until Windows 8) and in any implementation of TCP/IP, which is vulnerable to the Idle scan attack (including many IoT devices). NOTE: The vendor considers this a low severity issue."
                    }
                ],
                "affected": [
                    {
                        "vendor": "n/a",
                        "product": "n/a",
                        "versions": [
                            {
                                "version": "n/a",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://blog.pi3.com.pl/?p=850"
                    },
                    {
                        "url": "https://portswigger.net/daily-swig/blind-tcp-ip-hijacking-is-resurrected-for-windows-7"
                    },
                    {
                        "url": "https://pwnies.com/windows-7-blind-tcp-ip-hijacking/"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "type": "text",
                                "lang": "en",
                                "description": "n/a"
                            }
                        ]
                    }
                ]
            }
        }
    },
    {
        "containers": {
            "cna": {
                "title": "DirectX Graphics Kernel Elevation of Privilege Vulnerability",
                "datePublic": "2020-12-08T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:*:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:*:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_20H2:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2004:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "DirectX Graphics Kernel Elevation of Privilege Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Elevation of Privilege",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-31T17:59:48.219Z"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-17137"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "cveId": "CVE-2020-17137",
            "datePublished": "2020-12-09T23:36:52",
            "dateReserved": "2020-08-04T00:00:00",
            "dateUpdated": "2023-12-31T17:59:48.219Z",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "title": "Windows Overlay Filter Security Feature Bypass Vulnerability",
                "datePublic": "2020-12-08T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:*:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:*:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_20H2:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1909",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1909:*:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1909:*:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server, version 1909 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_1909:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1903 for 32-bit Systems",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "Unknown"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1903 for x64-based Systems",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "Unknown"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1903 for ARM64-based Systems",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "Unknown"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server, version 1903 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_1903:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2004:*:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "publication",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Overlay Filter Security Feature Bypass Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Security Feature Bypass",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-31T17:59:49.210Z"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-17139"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "cveId": "CVE-2020-17139",
            "datePublished": "2020-12-09T23:36:53",
            "dateReserved": "2020-08-04T00:00:00",
            "dateUpdated": "2023-12-31T17:59:49.210Z",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "title": "Windows Installer Elevation of Privilege Vulnerability",
                "datePublic": "2021-12-14T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.2366:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.2366:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.2366:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.2366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.2366:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.2366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.2366:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.2366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1909",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1909:10.0.18363.1977:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1909:10.0.18363.1977:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.18363.1977:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.18363.1977",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1415:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1415:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1415:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.405:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.405",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.19041.1415:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19041.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2004:10.0.19041.1415:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19041.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.1415:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.1415:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_20H2:10.0.19042.1415:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.376:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.376:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.376",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1415:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1415:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1415:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19145:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19145:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19145",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.4825:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.4825:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.4825",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.4825:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.4825",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.4825:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.4825",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.25796:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.25796:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20207:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20207:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20207:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20207",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21309",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21309",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21309",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.25796:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.25796:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23545:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23540:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23545",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23540",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23545:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23540:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23545",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23540",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20207:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20207",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20207:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20207",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Installer Elevation of Privilege Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Elevation of Privilege",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-28T18:12:39.512Z"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-43883"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"
                        }
                    }
                ]
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "cveId": "CVE-2021-43883",
            "datePublished": "2021-12-15T14:15:33",
            "dateReserved": "2021-11-16T00:00:00",
            "dateUpdated": "2023-12-28T18:12:39.512Z",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "containers": {
            "cna": {
                "title": "Windows Encrypting File System (EFS) Elevation of Privilege Vulnerability",
                "datePublic": "2021-12-14T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.2366:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.2366:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.2366:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.2366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.2366:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.2366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.2366:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.2366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1909",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1909:10.0.18363.1977:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1909:10.0.18363.1977:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.18363.1977:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.18363.1977",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1415:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1415:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.1415:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.405:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.405",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.19041.1415:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19041.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 2004",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2004:10.0.19041.1415:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19041.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.1415:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.1415:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_20H2:10.0.19042.1415:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.376:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.376:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.376",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1415:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1415:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.1415:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.1415",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19145:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19145:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19145",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.4825:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.4825:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.4825",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.4825:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.4825",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.4825:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.4825",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.25796:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.25796:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20207:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20207:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20207:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20207",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21309",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21309",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21309:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21309",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.25796:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.25796:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.25796",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23545:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23540:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23545",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23540",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23545:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.23540:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23545",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.23540",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20207:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20207",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20207:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20207",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Encrypting File System (EFS) Elevation of Privilege Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Elevation of Privilege",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-28T18:12:41.018Z"
                },
                "references": [
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-43893"
                    },
                    {
                        "tags": [
                            "x_refsource_MISC"
                        ],
                        "url": "http://packetstormsecurity.com/files/165560/Microsoft-Windows-EFSRPC-Arbitrary-File-Upload-Privilege-Escalation.html"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "cveId": "CVE-2021-43893",
            "datePublished": "2021-12-15T14:15:37",
            "dateReserved": "2021-11-16T00:00:00",
            "dateUpdated": "2023-12-28T18:12:41.018Z",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2022-44697",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "dateUpdated": "2023-12-20T17:28:09.392Z",
            "dateReserved": "2022-11-03T00:00:00",
            "datePublished": "2022-12-13T00:00:00"
        },
        "containers": {
            "cna": {
                "title": "Windows Graphics Component Elevation of Privilege Vulnerability",
                "datePublic": "2022-12-13T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3770:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3770:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3770:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3770",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3770:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3770",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3770:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3770",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2364:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2364:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2364:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1366:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2364:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2364:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1335:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1335:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.1335",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2364:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2364:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2364:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.993:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.993:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.993",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2364:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2364:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2364:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19624:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19624:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19624",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5582:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5582:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5582",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5582:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5582",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5582:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5582",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26266:sp1:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26266",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 7 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_7:6.1.7601.26266:sp1:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26266",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20721:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20721:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20721:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20721",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21815:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21815",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21815:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21815:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21815",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.21815:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.21815",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26266:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26266",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26266:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26266",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24018:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24018",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24018:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24018",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20721:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20721",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20721:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20721",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Graphics Component Elevation of Privilege Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Elevation of Privilege",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-20T17:28:09.392Z"
                },
                "references": [
                    {
                        "name": "Windows Graphics Component Elevation of Privilege Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-44697"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "state": "PUBLISHED",
            "cveId": "CVE-2022-44707",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "assignerShortName": "microsoft",
            "dateUpdated": "2023-12-20T17:28:11.466Z",
            "dateReserved": "2022-11-03T00:00:00",
            "datePublished": "2022-12-13T00:00:00"
        },
        "containers": {
            "cna": {
                "title": "Windows Kernel Denial of Service Vulnerability",
                "datePublic": "2022-12-13T08:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3770:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3770:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.3770:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3770",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3770:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3770",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.3770:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.3770",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2364:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2364:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H1:10.0.19043.2364:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19043.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1366:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1366",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 20H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2364:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_20H2:10.0.19042.2364:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19042.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1335:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.1335:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.1335",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2364:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2364:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.2364:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.993:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.993:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.993",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2364:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2364:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.2364:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.2364",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19624:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.19624:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.19624",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5582:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5582:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5582",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5582:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5582",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.5582:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.5582",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 8.1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20721:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_8.1:6.3.9600.20721:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_rt_8.1:6.3.9600.20721:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20721",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24018:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24018",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24018:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24018",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20721:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20721",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.20721:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.20721",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Kernel Denial of Service Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Denial of Service",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2023-12-20T17:28:11.466Z"
                },
                "references": [
                    {
                        "name": "Windows Kernel Denial of Service Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-44707"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "MEDIUM",
                            "baseScore": 6.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-36903",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "state": "PUBLISHED",
            "assignerShortName": "microsoft",
            "dateReserved": "2023-06-27T20:28:49.989Z",
            "datePublished": "2023-08-08T17:08:24.373Z",
            "dateUpdated": "2024-03-12T16:51:22.435Z"
        },
        "containers": {
            "cna": {
                "title": "Windows System Assessment Tool Elevation of Privilege Vulnerability",
                "datePublic": "2023-08-08T07:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1906:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1906",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1903",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.2295",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.2134",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.20107",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows System Assessment Tool Elevation of Privilege Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Elevation of Privilege",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-03-12T16:51:22.435Z"
                },
                "references": [
                    {
                        "name": "Windows System Assessment Tool Elevation of Privilege Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36903"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.8,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-36908",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "state": "PUBLISHED",
            "assignerShortName": "microsoft",
            "dateReserved": "2023-06-27T20:29:08.606Z",
            "datePublished": "2023-08-08T17:08:27.268Z",
            "dateUpdated": "2024-03-12T16:51:25.247Z"
        },
        "containers": {
            "cna": {
                "title": "Windows Hyper-V Information Disclosure Vulnerability",
                "datePublic": "2023-08-08T07:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1906:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1906",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1903",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.2295",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.2134",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.20107",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Windows Hyper-V Information Disclosure Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Information Disclosure",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-03-12T16:51:25.247Z"
                },
                "references": [
                    {
                        "name": "Windows Hyper-V Information Disclosure Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36908"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "MEDIUM",
                            "baseScore": 6.5,
                            "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-36909",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "state": "PUBLISHED",
            "assignerShortName": "microsoft",
            "dateReserved": "2023-06-27T20:29:08.606Z",
            "datePublished": "2023-08-08T17:08:27.831Z",
            "dateUpdated": "2024-03-12T16:51:25.832Z"
        },
        "containers": {
            "cna": {
                "title": "Microsoft Message Queuing Denial of Service Vulnerability",
                "datePublic": "2023-08-08T07:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1906:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1906",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1903",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.2295",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.2134",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.20107",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.22216",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.22216",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.22216",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Microsoft Message Queuing Denial of Service Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Denial of Service",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-03-12T16:51:25.832Z"
                },
                "references": [
                    {
                        "name": "Microsoft Message Queuing Denial of Service Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36909"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "MEDIUM",
                            "baseScore": 6.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    },
    {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2023-36912",
            "assignerOrgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
            "state": "PUBLISHED",
            "assignerShortName": "microsoft",
            "dateReserved": "2023-06-27T20:29:08.606Z",
            "datePublished": "2023-08-08T17:08:29.623Z",
            "dateUpdated": "2024-03-12T16:51:27.507Z"
        },
        "containers": {
            "cna": {
                "title": "Microsoft Message Queuing Denial of Service Vulnerability",
                "datePublic": "2023-08-08T07:00:00+00:00",
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1809",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_1809:10.0.17763.4737:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2019 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.4737:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.17763.4737",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2022",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1906:*:*:*:*:*:*:*",
                            "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.1903:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1906",
                                "versionType": "custom",
                                "status": "affected"
                            },
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.20348.1903",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_11_21H2:10.0.22000.2295:*:*:*:*:*:arm64:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22000.2295",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 21H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_21H2:10.0.19044.3324:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "ARM64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19044.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 11 version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_11_22H2:10.0.22621.2134:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "ARM64-based Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.22621.2134",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 22H2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:arm64:*",
                            "cpe:2.3:o:microsoft:windows_10_22H2:10.0.19045.3324:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems",
                            "ARM64-based Systems",
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.19045.3324",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1507",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20107:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.10240.20107",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows 10 Version 1607",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x86:*",
                            "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.6167:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2016 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2016:10.0.14393.6167:*:*:*:*:*:*:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "10.0.0",
                                "lessThan": "10.0.14393.6167",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "32-bit Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.22216",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 Service Pack 2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x64:*",
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "32-bit Systems",
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.22216",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008  Service Pack 2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_sp2:6.0.6003.22216:*:*:*:*:*:x86:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.0.6003.22216",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.1.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2008 R2 Service Pack 1 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2008_R2:6.1.7601.26664:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.0.0",
                                "lessThan": "6.1.7601.26664",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.24414:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.2.0",
                                "lessThan": "6.2.9200.24414",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    },
                    {
                        "vendor": "Microsoft",
                        "product": "Windows Server 2012 R2 (Server Core installation)",
                        "cpes": [
                            "cpe:2.3:o:microsoft:windows_server_2012_R2:6.3.9600.21503:*:*:*:*:*:x64:*"
                        ],
                        "platforms": [
                            "x64-based Systems"
                        ],
                        "versions": [
                            {
                                "version": "6.3.0",
                                "lessThan": "6.3.9600.21503",
                                "versionType": "custom",
                                "status": "affected"
                            }
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "value": "Microsoft Message Queuing Denial of Service Vulnerability",
                        "lang": "en-US"
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Denial of Service",
                                "lang": "en-US",
                                "type": "Impact"
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "f38d906d-7342-40ea-92c1-6c4a2c6478c8",
                    "shortName": "microsoft",
                    "dateUpdated": "2024-03-12T16:51:27.507Z"
                },
                "references": [
                    {
                        "name": "Microsoft Message Queuing Denial of Service Vulnerability",
                        "tags": [
                            "vendor-advisory"
                        ],
                        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36912"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en-US",
                                "value": "GENERAL"
                            }
                        ],
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseSeverity": "HIGH",
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C"
                        }
                    }
                ]
            }
        }
    }
]