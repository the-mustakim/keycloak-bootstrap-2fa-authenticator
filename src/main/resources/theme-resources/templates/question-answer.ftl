<#import "template.ftl" as layout>

<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
    <#-- Use a standard header or your custom message -->
        ${msg("Enter your answer", "Security Question")}
    <#elseif section = "form">
        <form action="${url.loginAction}" method="post">
            <#-- CRITICAL: Hidden fields for Keycloak flow state -->
            <input type="hidden" name="credentialId" value="${credentialId!''}" />
            <input type="hidden" name="execution" value="${execution!''}" />

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
                <input type="submit"
                       class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                       value="${msg("doSubmit")}" />
            </div>
        </form>
    </#if>
</@layout.registrationLayout>