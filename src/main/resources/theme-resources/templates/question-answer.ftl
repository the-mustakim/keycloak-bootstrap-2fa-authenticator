<#import "template.ftl" as layout>

<#-- Change displayInfo to true so the 'Try Another Way' link has a place to live -->
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("Enter your answer", "Security Question")}
    <#elseif section = "form">
        <form action="${url.loginAction}" method="post">
            <#-- Hidden fields to maintain flow state -->
            <input type="hidden" name="credentialId" value="${credentialId!''}" />

            <div class="${properties.kcFormGroupClass!}">
                <label class="${properties.kcLabelClass!}">
                    ${question}
                </label>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="password"
                           id="secret_answer"
                           name="secret_answer"
                           class="${properties.kcInputClass!}"
                           autofocus
                           autocomplete="off"
                           required />
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input type="submit"
                           class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           value="${msg("doSubmit")}" />
                </div>
            </div>
        </form>

    <#-- This section is crucial for rendering 'Try Another Way' -->
    <#elseif section = "info" >
        <#if realm.password && social.providers??>
        <#-- Keycloak automatically injects 'Try Another Way' here if requirements are met -->
        </#if>
    </#if>
</@layout.registrationLayout>