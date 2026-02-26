/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.common;

import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.config.ConfigKey;
import org.apache.kerby.config.Resource;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * A krb5.conf format support.
 */
public class Krb5Conf extends Conf {
    /**
     * The regex to split a config value(string) to a list 
     * of config value(string list).
     */
    private static final String LIST_SPLITTER = " |,";
    private Map<String, Object> krb5Map;

    /**
     * Load Kerberos configuration from a file on disk.
     *
     * @param krb5File the krb5.conf file
     * @throws IOException if the file cannot be read
     */
    public void addKrb5Config(File krb5File) throws IOException {
        Krb5Parser krb5Parser = new Krb5Parser(krb5File);
        krb5Parser.load();
        krb5Map = krb5Parser.getItems();
        addResource(Resource.createMapResource(krb5Map));
    }

    /**
     * Load Kerberos configuration from an {@link InputStream}.
     *
     * <p>This allows callers to supply krb5.conf content from in-memory sources
     * (e.g. a value read from a secrets manager) without requiring a file on disk
     * or the JVM-global {@code java.security.krb5.conf} system property.
     * The caller is responsible for closing the stream after this method returns.
     *
     * @param inputStream stream of krb5.conf content
     * @throws IOException if the stream cannot be read
     */
    public void addKrb5Config(InputStream inputStream) throws IOException {
        Krb5Parser krb5Parser = new Krb5Parser(inputStream);
        krb5Parser.load();
        krb5Map = krb5Parser.getItems();
        addResource(Resource.createMapResource(krb5Map));
    }

    /**
     * Load Kerberos configuration from a {@link String}.
     *
     * <p>This is the most convenient form for embedding krb5.conf content
     * directly in connector properties files or loading it from a secrets manager,
     * removing the need for a separate configuration file on disk.
     *
     * @param configContent krb5.conf content as a string
     * @throws IOException if the content cannot be parsed
     */
    public void addKrb5Config(String configContent) throws IOException {
        Krb5Parser krb5Parser = new Krb5Parser(configContent);
        krb5Parser.load();
        krb5Map = krb5Parser.getItems();
        addResource(Resource.createMapResource(krb5Map));
    }

    protected String getString(ConfigKey key, boolean useDefault,
                            String... sections) {
        String value = getString(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getString(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (String) key.getDefaultValue();
        }

        return value;
    }

    protected Boolean getBoolean(ConfigKey key, boolean useDefault,
                                 String... sections) {
        Boolean value = getBoolean(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getBoolean(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (Boolean) key.getDefaultValue();
        }

        return value;
    }

    protected Long getLong(ConfigKey key, boolean useDefault,
                           String... sections) {
        Long value = getLong(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getLong(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (Long) key.getDefaultValue();
        }

        return value;
    }

    protected Integer getInt(ConfigKey key, boolean useDefault,
                             String... sections) {
        Integer value = getInt(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getInt(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (Integer) key.getDefaultValue();
        }

        return value;
    }

    protected List<EncryptionType> getEncTypes(ConfigKey key, boolean useDefault,
                                               String... sections) {
        String[] encTypesNames = getStringArray(key, useDefault, sections);
        return getEncryptionTypes(encTypesNames);
    }

    protected List<EncryptionType> getEncryptionTypes(String[] encTypeNames) {
        return getEncryptionTypes(Arrays.asList(encTypeNames));
    }

    protected List<EncryptionType> getEncryptionTypes(List<String> encTypeNames) {
        List<EncryptionType> results = new ArrayList<>(encTypeNames.size());

        for (String eTypeName : encTypeNames) {
            EncryptionType eType = EncryptionType.fromName(eTypeName);
            if (eType != EncryptionType.NONE) {
                results.add(eType);
            }
        }

        return results;
    }

    protected String[] getStringArray(ConfigKey key, boolean useDefault,
                                      String... sections) {
        String value = getString(key, useDefault, sections);
        if (value != null) {
            return value.split(LIST_SPLITTER);
        }
        return new String[]{};
    }

    protected Object getSection(String sectionName) {
        if (krb5Map != null) {
            for (Map.Entry<String, Object> entry : krb5Map.entrySet()) {
                if (entry.getKey().equals(sectionName)) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }
}
