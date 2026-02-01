<#import "template.ftl" as layout>

<@layout.loginLayout section>
    <#if section = "header">
        ${msg("loginSecretQuestionTitle","Security Question")}
    <#elseif section = "form">
        <form action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label class="${properties.kcLabelClass!}">
                    ${question}
                </label>
                <input type="password"
                       name="secret_answer"
                       class="${properties.kcInputClass!}"
                       autofocus
                       autocomplete="off"
                       required />
            </div>

            <input type="submit"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}"
                   value="${msg("doSubmit")}" />
        </form>
    </#if>
</@layout.loginLayout>
