package com.aixcc.struts.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.HashMap;
import java.util.Map;
import com.sun.el.ExpressionFactoryImpl;
import jakarta.el.ArrayELResolver;
import jakarta.el.BeanELResolver;
import jakarta.el.CompositeELResolver;
import jakarta.el.ELResolver;
import jakarta.el.ListELResolver;
import jakarta.el.MapELResolver;
import jakarta.el.ResourceBundleELResolver;

import org.apache.struts2.ActionSupport;
import org.apache.struts2.action.ServletRequestAware;
import org.apache.tiles.el.ELAttributeEvaluator;
import org.apache.tiles.core.evaluator.AttributeEvaluator;
import org.apache.tiles.api.Attribute;
import org.apache.tiles.api.Expression;
import org.apache.tiles.request.Request;
import org.apache.tiles.request.ApplicationContext;

import org.easymock.EasyMock;

public class StrutsOne {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        Map<String, String> params = new HashMap<>();
        int numParams = data.consumeInt(0, 10);
        for (int i = 0; i < numParams; i++) {
            String key = data.consumeString(100);
            String value = data.consumeString(100);
            params.put(key, value);
        }

        ELAttributeEvaluator evaluator = new ELAttributeEvaluator();
        evaluator.setExpressionFactory(new ExpressionFactoryImpl());

        ELResolver elResolver = new CompositeELResolver() {
            {
                BeanELResolver beanElResolver = new BeanELResolver(false);
                add(new ArrayELResolver(false));
                add(new ListELResolver(false));
                add(new MapELResolver(false));
                add(new ResourceBundleELResolver());
                add(beanElResolver);
            }
        };
        evaluator.setResolver(elResolver);

        Request request = EasyMock.createMock(Request.class);
        ApplicationContext applicationContext = EasyMock.createMock(ApplicationContext.class);
        EasyMock.expect(request.getApplicationContext()).andReturn(applicationContext).anyTimes();
        EasyMock.expect(request.getParam()).andReturn(params).anyTimes();

        EasyMock.replay(request, applicationContext);

        CalculateAction action = new CalculateAction(evaluator, request);
        action.execute();
    }


    public static class CalculateAction {

        private final AttributeEvaluator evaluator;
        private final Request request;

        public CalculateAction(AttributeEvaluator evaluator, Request request) {
            this.evaluator = evaluator;
            this.request = request;
        }

        public String execute() {
            // Check for operands.
            Map<String, String> params = request.getParam();
            if (!params.containsKey("operand")) {
                this.message = "operand is missing";
                return ActionSupport.ERROR;
            }
            int operand;
            try {
                operand = Integer.parseInt(params.get("operand"));
            } catch (NumberFormatException e) {
                this.message = "operand is not a valid integer";
                return ActionSupport.ERROR;
            }
            if (operand <= 0) {
                this.message = "operand must be positive";
                return ActionSupport.ERROR;
            }

            if (!params.containsKey("result")) {
                this.message = "result is missing";
                return ActionSupport.ERROR;
            }

            String realResult = (operand * 2) + "";
            if (!realResult.equals(params.get("result"))) {
                this.message = "result is not correct";
                return ActionSupport.ERROR;
            }

            if (!params.containsKey("name")) {
                this.message = "name is missing";
                return ActionSupport.ERROR;
            }

            Attribute nameAttribute = new Attribute();
            nameAttribute.setValue(params.get("name"));

            try {
                this.message = "Congratulations " +
                    evaluator.evaluate(nameAttribute, request) +
                    ", you have successfully calculated the result!";
            } catch (Exception e) {
                this.message = "name evaluation failed: " + e.getMessage();
                return ActionSupport.ERROR;
            }
            return ActionSupport.SUCCESS;
        }

        private String message;

        public String getMessage() {
            return this.message;
        }

    }

}
