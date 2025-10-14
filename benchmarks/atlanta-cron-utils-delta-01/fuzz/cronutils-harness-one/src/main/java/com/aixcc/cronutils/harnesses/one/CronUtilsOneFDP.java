package com.aixcc.cronutils.harnesses.one;

import com.cronutils.validation.Cron;
import com.cronutils.model.CronType;
import java.util.Set;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class CronUtilsOneFDP {

  public static class Job {
    @Cron(type = CronType.SPRING)
    private String cronExpression;

    String getCronExpression() {
      return cronExpression;
    }

    void setCronExpression(String cronExpression) {
      this.cronExpression = cronExpression;
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    //input = "java.lang.Runtime.getRuntime().exec('touch /tmp/pwned'); // 4 5 [${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval(validatedValue)}]";
    Job job = new Job();
    job.setCronExpression(input);

    ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
    Validator validator = factory.getValidator();

    Set<ConstraintViolation<Job>> constraintViolations = validator.validate(job);
    String errmsg = constraintViolations.iterator().next().getMessage();
    System.out.println(errmsg);
  }
}
