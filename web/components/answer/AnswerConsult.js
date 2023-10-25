import { QuestionType } from '@prisma/client'
import { Stack } from '@mui/material'
import ConsultEssay from './ConsultEssay'
import ConsultWeb from './ConsultWeb'
import ConsultCode from './ConsultCode'
import CompareTrueFalse from './CompareTrueFalse'
import ConsultDatabase from './ConsultDatabase'
import ConsultMultipleChoice from './ConsultMultipleChoice'
/*
    this component is used to display the student answer and grading to a question in the context of the student's consultation
    it displays the answer and grading, but not the solutions
    MultipleChoice:
    In the case of the multiple choice question, it displays all the options and the student's answer
    remember that the student answer only contains options selected by the student (not all options)
    this is why we passe question as a prop to this component, so that we can display all options and check the ones selected by the student
    it is important not to fetch the "isCorrect" property of the option
* */
const AnswerConsult = ({ id, questionType, question, answer }) => {
  return (
    <Stack height="100%" overflow="auto">
      {answer &&
        (
          (questionType === QuestionType.trueFalse && (
            <CompareTrueFalse mode="consult" answer={answer.isTrue} />
          )) ||
          (questionType === QuestionType.multipleChoice && answer.options && (
            <ConsultMultipleChoice
              id={id}
              options={question.multipleChoice.options}
              answer={answer.options}
            />
          )) ||
          (questionType === QuestionType.essay && (
            <ConsultEssay content={answer.content} />
          )) ||
          (questionType === QuestionType.code && (
            <ConsultCode files={answer.files} tests={answer.testCaseResults} />
          )) ||
          (questionType === QuestionType.web && (
            <ConsultWeb answer={answer} />
          )) ||
          (questionType === QuestionType.database && (
              <ConsultDatabase 
                queries={answer.queries} 
                />
          ))
          
        )}
    </Stack>
  )
}

export default AnswerConsult
