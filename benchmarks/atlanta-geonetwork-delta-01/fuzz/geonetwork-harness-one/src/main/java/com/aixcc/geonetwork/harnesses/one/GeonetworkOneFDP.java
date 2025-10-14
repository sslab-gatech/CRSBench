package com.aixcc.geonetwork.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;

import java.io.StringReader;
import jeeves.server.context.ServiceContext;

import org.fao.geonet.ApplicationContextHolder;
import org.fao.geonet.kernel.harvest.harvester.AbstractHarvester;
import org.fao.geonet.kernel.harvest.harvester.localfilesystem.LocalFilesystemHarvester;
import org.fao.geonet.kernel.harvest.harvester.localfilesystem.LocalFilesystemParams;
import org.fao.geonet.kernel.setting.HarvesterSettingsManager;
import org.fao.geonet.kernel.setting.Settings;
import org.fao.geonet.kernel.setting.SettingManager;
import org.fao.geonet.repository.HarvesterSettingRepository;
import org.fao.geonet.repository.LanguageRepository;
import org.fao.geonet.repository.SourceRepository;
import org.fao.geonet.resources.Resources;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import org.mockito.Mockito;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.*;


public class GeonetworkOneFDP {
    static MockedStatic<ApplicationContextHolder> contextHolder;
    static ConfigurableApplicationContext appContext;
    static ServiceContext serviceContext;    
    static HarvesterSettingsManager harvesterManager;
    static SettingManager manager;
    static HarvesterSettingRepository harvesterRepo;
    static LanguageRepository langRepo;
    static SourceRepository sourceRepo;
    static LocalFilesystemHarvester harvester;
    static Resources resources;

    public static void fuzzerInitialize() {
        contextHolder = Mockito.mockStatic(ApplicationContextHolder.class);
        appContext = Mockito.mock(ConfigurableApplicationContext.class);
        serviceContext = Mockito.mock(ServiceContext.class);
        manager = Mockito.mock(SettingManager.class);
        harvesterRepo = Mockito.mock(HarvesterSettingRepository.class);
        langRepo = Mockito.mock(LanguageRepository.class);
        sourceRepo = Mockito.mock(SourceRepository.class);
        resources = Mockito.mock(Resources.class);

        harvesterManager = new HarvesterSettingsManager();
        harvester = new LocalFilesystemHarvester();
        
        Mockito.when(ApplicationContextHolder.get()).thenReturn(appContext);
        when(appContext.getBean(SettingManager.class)).thenReturn(manager);
        when(appContext.getBean(HarvesterSettingRepository.class)).thenReturn(harvesterRepo);
        when(appContext.getBean(LanguageRepository.class)).thenReturn(langRepo);
        when(appContext.getBeanNamesForType(LocalFilesystemHarvester.class)).thenReturn(new String[]{""});
        when(serviceContext.getBean("", AbstractHarvester.class)).thenReturn(harvester);
        when(serviceContext.getBean(HarvesterSettingsManager.class)).thenReturn(harvesterManager);
        when(serviceContext.getBean(SourceRepository.class)).thenReturn(sourceRepo);
        when(serviceContext.getBean(Resources.class)).thenReturn(resources);
        when(serviceContext.getApplicationContext()).thenReturn(appContext);
        when(manager.getValue(Settings.SYSTEM_SERVER_TIMEZONE, true)).thenReturn("UTC");
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
        try {
            new GeonetworkOneFDP().fuzz(data);
        } catch (FuzzerSecurityIssueLow |
                 FuzzerSecurityIssueMedium |
                 FuzzerSecurityIssueHigh |
                 FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Throwable t) {
        }
    }

    public void fuzz(FuzzedDataProvider data) throws Throwable {
        byte[] b = data.consumeRemainingAsBytes();
        SAXBuilder saxBuilder = new SAXBuilder();
        Document document = saxBuilder.build(new StringReader(new String(b)));
        Element element = document.getRootElement();
        LocalFilesystemHarvester harvester = (LocalFilesystemHarvester)AbstractHarvester.create("", serviceContext);
        harvester.add(element);
        harvester.doHarvest(null);
    }
}
