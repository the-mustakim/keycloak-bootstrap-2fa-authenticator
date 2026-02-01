<#import "template.ftl" as layout>

<@layout.registrationLayout displayInfo=false displayMessage=true displayRequiredFields=false; section>
    <#if section = "header">
        ${msg("Register Your Secret Question","Configure Secret Question")}
    <#elseif section = "form">
        <form action="${url.loginAction}" method="post">

            <div class="${properties.kcFormGroupClass!}">
                <label class="${properties.kcLabelClass!}">
                    ${msg("Choose Secret Question","Secret Question")}
                </label>
                <select name="question" class="${properties.kcInputClass!}" required>
                    <option value="" disabled selected>Select a question</option>
                    <option value="What is your favorite food?">What is your favorite food?</option>
                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                </select>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <label class="${properties.kcLabelClass!}">
                    ${msg("Secret Answer","Answer")}
                </label>
                <input type="password"
                       name="secret_answer"
                       class="${properties.kcInputClass!}"
                       autocomplete="off"
                       required />
            </div>

            <input type="submit"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}"
                   value="${msg("doSubmit")}" />
        </form>
    </#if>
</@layout.registrationLayout>
