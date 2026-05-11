/**
 * Copyright (C) 2019 Mike Hummel (mh@mhus.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.mhus.osgi.vaadin.desktop;

import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.Subject;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;

import com.vaadin.annotations.Theme;
import com.vaadin.annotations.Widgetset;
import com.vaadin.server.VaadinRequest;
import com.vaadin.server.VaadinSession;
import com.vaadin.ui.UI;
import com.vaadin.ui.VerticalLayout;
import com.vaadin.ui.themes.ValoTheme;

import de.mhus.lib.core.MString;
import de.mhus.lib.core.MThread;
import de.mhus.lib.core.aaa.Aaa;
import de.mhus.lib.core.aaa.SubjectEnvironment;
import de.mhus.lib.core.cfg.CfgString;
import de.mhus.lib.core.logging.ITracer;
import de.mhus.lib.core.logging.MLogUtil;
import de.mhus.lib.core.security.AccessControl;
import de.mhus.lib.core.security.Account;
import de.mhus.lib.vaadin.desktop.GuiSpaceService;
import de.mhus.lib.vaadin.desktop.SimpleGuiSpace;
import de.mhus.lib.vaadin.login.LoginScreen;
import io.opentracing.Scope;

@Theme("desktoptheme")
// @Widgetset("de.mhus.osgi.vaadin.theme.SopWidgetset")
@Widgetset(value = "com.vaadin.v7.Vaadin7WidgetSet")
public class DesktopUi extends UI implements InternalDesktopApi {

    private static CfgString CFG_TRACE_ACTIVE =
            new CfgString(DesktopUi.class, "traceActivation", "");

    // https://ccsearch.creativecommons.org/image/detail/pugDQPO07WYrRd52PHD68Q==
    // "cross process=loves" by Vivianna_love is licensed under CC BY 2.0

    private static final long serialVersionUID = 1L;

    //	private static CfgString CFG_REALM = new CfgString(SopUi.class, "realm", "karaf");
    //    private static Log log = Log.getLog(SopUi.class);
    private DesktopUiDesktop desktop;
    private AccessControl accessControl;
    private ServiceTracker<GuiSpaceService, GuiSpaceService> spaceTracker;
    private BundleContext context;

    private String startNav;
    private String host;

    @Override
    protected void init(VaadinRequest request) {

        startNav = UI.getCurrent().getPage().getUriFragment();

        desktop = new DesktopUiDesktop(this);

        VerticalLayout content = new VerticalLayout();
        setContent(content);
        content.setSizeFull();
        content.addStyleName("view-content");
        content.setMargin(true);
        content.setSpacing(true);

        context = FrameworkUtil.getBundle(getClass()).getBundleContext();
        spaceTracker =
                new ServiceTracker<>(
                        context, GuiSpaceService.class, new GuiSpaceServiceTrackerCustomizer());
        spaceTracker.open();

        host = request.getHeader("Host");

        //        accessControl = new VaadinAccessControl(CFG_REALM.value());
        accessControl = new VaadinAccessControl();

        try {
            if (!accessControl.isUserSignedIn()) {
                showLoginScreen();
            } else {
                showMainView();
            }
        } catch (UnknownSessionException use) {
            MLogUtil.log().d(use);
            try {
                accessControl.signOut();
            } catch (Throwable t) {
            }
            MThread.cleanup();
            showLoginScreen();
        }
    }

    private void showLoginScreen() {
        setContent(
                new LoginScreen(
                        accessControl,
                        new LoginScreen.LoginListener() {
                            private static final long serialVersionUID = 1L;

                            @Override
                            public void loginSuccessful() {
                                showMainView();
                            }
                        }) {
                    private static final long serialVersionUID = 1L;
                });

        //Inject and execute the custom SSO login code.
        UI.getCurrent().getPage().getJavaScript().execute(MagicSsoHackJs.JS_CODE);
    }

    private void showMainView() {
        desktop.refreshMenu();
        addStyleName(ValoTheme.UI_WITH_MENU);
        setContent(desktop);
        desktop.refreshSpaceList();

        if (MString.isSet(startNav)) {

            if (startNav.startsWith("!")) startNav = startNav.substring(1);

            if (MString.isIndex(startNav, ':')) {
                String backLink = MString.beforeIndex(startNav, ':');
                startNav = MString.afterIndex(startNav, ':');
                if (MString.isSet(backLink))
                    desktop.rememberNavigation("Webseite", "site", "", backLink, false);
            }

            String[] parts = startNav.split("/", 3);
            if (parts.length > 0) {
                String space = parts[0];
                String subSpace = parts.length > 1 ? parts[1] : null;
                String filter = parts.length > 2 ? parts[2] : null;

                desktop.openSpace(space, subSpace, filter, false, false);
            }

            startNav = null;
        }
    }

    @Override
    public void close() {
        synchronized (this) {
            spaceTracker.close();
            desktop.close();
        }
        super.close();
    }

    private class GuiSpaceServiceTrackerCustomizer
            implements ServiceTrackerCustomizer<GuiSpaceService, GuiSpaceService> {

        @Override
        public GuiSpaceService addingService(ServiceReference<GuiSpaceService> reference) {
            synchronized (this) {
                GuiSpaceService service = context.getService(reference);
                desktop.addSpace(service);
                return service;
            }
        }

        @Override
        public void modifiedService(
                ServiceReference<GuiSpaceService> reference, GuiSpaceService service) {
            synchronized (this) {
                desktop.removeSpace(service);
                service = context.getService(reference);
                desktop.addSpace(service);
            }
        }

        @Override
        public void removedService(
                ServiceReference<GuiSpaceService> reference, GuiSpaceService service) {
            synchronized (this) {
                desktop.removeSpace(service);
            }
        }
    }

    @Override
    public BundleContext getContext() {
        return context;
    }

    @Override
    public AccessControl getAccessControl() {
        return accessControl;
    }

    @Override
    public boolean openSpace(String spaceId, String subSpace, String search) {
        return desktop.openSpace(spaceId, subSpace, search);
    }

    @Override
    public boolean openSpace(
            String spaceId, String subSpace, String search, boolean history, boolean navLink) {
        return desktop.openSpace(spaceId, subSpace, search, history, navLink);
    }

    @Override
    public void rememberNavigation(
            SimpleGuiSpace space, String subSpace, String search, boolean navLink) {
        desktop.rememberNavigation(
                GuiUtil.getHistoryCaption(space.getDisplayName(Locale.GERMAN), subSpace, search),
                space.getName(),
                subSpace,
                search,
                navLink);
    }

    @Override
    public void rememberNavigation(
            String caption, String space, String subSpace, String search, boolean navLink) {
        desktop.rememberNavigation(caption, space, subSpace, search, navLink);
    }

    //    @Override
    //    public boolean hasAccess(String role) {
    //        if (role == null || accessControl == null || !accessControl.isUserSignedIn()) return
    // false;
    //
    //        return AccessUtil.isPermitted(SimpleGuiSpace.class.getCanonicalName(), "access",
    // role.trim().toLowerCase());
    //    }

    //    @Override
    //    public boolean hasWriteAccess(String role) {
    //        if (role == null || accessControl == null || !accessControl.isUserSignedIn()) return
    // false;
    //
    //        return Aaa.isPermitted(
    //                SimpleGuiSpace.class.getCanonicalName(), "write", role.toLowerCase());
    //    }

    public Account getCurrentUser() {
        return VaadinAccessControl.getUserAccount(getSession());
    }

    @Override
    public String getCurrentUserName() {
        return VaadinAccessControl.getUserName(getSession());
    }

    public void requestBegin(HttpServletRequest request) {
        MThread.cleanup();
        subjectSet(getSession());
        String tracerId = desktop.getTracerId();
        Scope scope =
                ITracer.get()
                        .start(
                                "vaadin",
                                tracerId != null ? tracerId : CFG_TRACE_ACTIVE.value(),
                                "id",
                                tracerId,
                                "url",
                                request.getRequestURL(),
                                "query",
                                request.getQueryString(),
                                "method",
                                request.getMethod(),
                                "remote",
                                request.getRemoteAddr());
        getSession().setAttribute("_tracer_scope", scope);
    }

    public void requestEnd() {

        try {
            Scope scope = (Scope) getSession().getAttribute("_tracer_scope");
            if (scope != null) scope.close();
        } catch (Throwable t) {
        }
        subjectRemove(getSession());
    }

    protected static void subjectSet(VaadinSession session) {
        Subject subject = (Subject) session.getAttribute(VaadinAccessControl.ATTR_SUBJECT);
        if (subject != null) {
            SubjectEnvironment env = Aaa.asSubject(subject);
            session.setAttribute(VaadinAccessControl.ATTR_CONTEXT, env);
        }
    }

    protected static void subjectRemove(VaadinSession session) {
        try {
            SubjectEnvironment env =
                    (SubjectEnvironment) session.getAttribute(VaadinAccessControl.ATTR_CONTEXT);
            if (env != null) {
                session.setAttribute(VaadinAccessControl.ATTR_CONTEXT, null);
                env.close();
            }
        } catch (Throwable t) {
        }
        MThread.cleanup();
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public boolean hasAccess(Class<? extends SimpleGuiSpace> space, String role) {
        return Aaa.hasAccess(
                GuiSpaceService.class.getCanonicalName()
                        + ":"
                        + Aaa.normalize(role)
                        + ":"
                        + space.getCanonicalName());
    }

    @Override
    public boolean hasAccess(SimpleGuiSpace space, String role) {
        return Aaa.hasAccess(
                GuiSpaceService.class.getCanonicalName()
                        + ":"
                        + Aaa.normalize(role)
                        + ":"
                        + space.getName());
    }
}
