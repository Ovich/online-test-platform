import { ListItemIcon, ListItemText, MenuItem, MenuList, Typography } from "@mui/material";
import { EvaluationPhase, StudentAnswerStatus, StudentQuestionGradingStatus, UserOnEvaluationAccessMode } from "@prisma/client";

import SettingsSharpIcon from '@mui/icons-material/SettingsSharp';
import FormatListNumberedSharpIcon from '@mui/icons-material/FormatListNumberedSharp';
import PeopleSharpIcon from '@mui/icons-material/PeopleSharp';
import ModelTrainingSharpIcon from '@mui/icons-material/ModelTrainingSharp';
import GradingSharpIcon from '@mui/icons-material/GradingSharp';
import { Box, Stack } from "@mui/system";
import { phaseGreaterThan } from "../phases";
import StatusDisplay from "@/components/feedback/StatusDisplay";


const EvaluationSideMenu = ({ evaluation, composition, attendance, progress, results, currentPhase, active, setActive }) => {

    const overallProgress = (progress) => {
      let totalAnswers = 0;
      let completedAnswers = 0;

      progress.forEach(question => {
          totalAnswers += question.question.studentAnswer.length;
          completedAnswers += question.question.studentAnswer.filter(answer => answer.status !== StudentAnswerStatus.MISSING).length;
      });

      return Math.round((completedAnswers / totalAnswers) * 100);
    };

    const overallGrading = (results) => {
      let totalGraded = 0;
      let graded = 0;

      results.forEach(question => {
          totalGraded += question.question.studentAnswer.length;
          graded += question.question.studentAnswer.filter(answer => answer.studentGrading.signedBy).length;
      });

      return Math.round((graded / totalGraded) * 100);
    }

    return (

      <MenuList>
          <EvaluationMenuItem
              icon={SettingsSharpIcon}
              label="Settings"
              phase={EvaluationPhase.SETTINGS}
              currentPhase={currentPhase}
              active={active}
              setActive={setActive}
              menuKey="settings"
              summary={<SettingsSummary evaluation={evaluation} />}
          />
          <EvaluationMenuItem
              icon={FormatListNumberedSharpIcon}
              label="Composition"
              details={`${composition?.length || 0} questions`}
              phase={EvaluationPhase.COMPOSITION}
              currentPhase={currentPhase}
              active={active}
              setActive={setActive}
              menuKey="composition"
              summary={<CompositionSummary evaluation={evaluation} composition={composition} />}
          />
          <EvaluationMenuItem
              icon={PeopleSharpIcon}
              label="Attendance"
              details={`${attendance.registered.length} students`}
              phase={EvaluationPhase.REGISTRATION}
              currentPhase={currentPhase}
              active={active}
              setActive={setActive}
              menuKey="attendance"
              summary={<AttendanceSummary attendance={attendance} />}
          />
          <EvaluationMenuItem
              icon={ModelTrainingSharpIcon}
              label="Student Progress"
              details={`${overallProgress(progress)}%`}
              phase={EvaluationPhase.IN_PROGRESS}
              currentPhase={currentPhase}
              active={active}
              setActive={setActive}
              menuKey="progress"
              summary={<ProgressSummary progress={progress} />}
          />
          <EvaluationMenuItem
              icon={GradingSharpIcon}
              label="Grading & Results"
              details={`${overallGrading(results)}%`}
              phase={EvaluationPhase.GRADING}
              currentPhase={currentPhase}
              active={active}
              setActive={setActive}
              menuKey="results"
              summary={<GradingSummary results={results} />}
          />
      </MenuList>
    
    );
};


const EvaluationMenuItem = ({ icon: Icon, label, details, summary, phase, currentPhase, active, setActive, menuKey }) => {
  
  const renderStatus = () => {
    if (phaseGreaterThan(currentPhase, phase)) {
      return <StatusDisplay status={"SUCCESS"} />;
    } else if (currentPhase === phase) {
      return <StatusDisplay status={"NEUTRAL"} />;
    }
    return <StatusDisplay status={"EMPTY"} />;
  };

  const disabled = phaseGreaterThan(phase, currentPhase)
  
  return (
    <>
    <MenuItem 
      selected={active === menuKey} 
      onClick={() => setActive(menuKey)} 
      disabled={disabled}
    >
      <ListItemIcon>
        <Icon fontSize="small" />
      </ListItemIcon>
      <ListItemText>{label}</ListItemText>
      {details && (
        <Typography variant="body2" color="text.secondary">
          {details}
        </Typography>
      )}
      <Box ml={0.5}>
        {renderStatus()}
      </Box>    
    </MenuItem>
    {summary && !disabled && (
        <Stack pt={1} pl={2} pb={2}>
            {summary}
        </Stack>
        )}
    </>
  );
};

const SettingsSummary = ({ evaluation }) => {

    const isRestricted = evaluation.accessMode === UserOnEvaluationAccessMode.LINK_AND_ACCESS_LIST
  
    const isLabelDefined = evaluation.label && evaluation.label.length > 0
  
    return (
      <Stack spacing={0}>
        {!isLabelDefined && (
          <Typography variant="caption" color="error">
            - Label is required.
          </Typography>
        )}
        {isRestricted ? (
          <Typography variant="caption">
            - Restricted access
          </Typography>
        ) : (
          <Typography variant="caption">
            - Anyone with the link can access
          </Typography>
        )}
        {isRestricted && evaluation.accessList.length > 0 && (
          <Typography variant="caption" pl={2}>
            - Access list contains {evaluation.accessList.length} students
          </Typography>
        )}
        {evaluation.conditions ? (
          <Typography variant="caption">
            - Conditions are set.
          </Typography>
        ) : (
          <Typography variant="caption">
            - No conditions are set.
          </Typography>
        )}
        {evaluation.durationHours > 0 || evaluation.durationMins > 0 ? (
          <Typography variant="caption">
            - Duration: {evaluation.durationHours}h {evaluation.durationMins}m.
          </Typography>
        ) : (
          <Typography variant="caption">
            - No duration set.
          </Typography>
        )}
      </Stack>
    )
  }
  
  const CompositionSummary = ({ evaluation, composition }) => {
    return (
      <Stack>
        <Typography 
          variant="caption"
          color={composition?.length === 0 ? "error" : "text.primary"}
        >
          - {composition?.length} questions.
        </Typography>
        <Typography variant="caption">- {composition?.reduce((acc, q) => acc + q.points, 0)} points.</Typography>
         {phaseGreaterThan(evaluation.phase, EvaluationPhase.COMPOSITION) ? (
            <>
            <Typography variant="caption"> - Composition is completed.</Typography>
            <Typography variant="caption"> - Questions are copied to the evaluation.</Typography>
            </>
          ) : (
            <>
            <Typography variant="caption">- Composition is open for changes.</Typography>
            <Typography variant="caption">- Questions are linked to the evaluation.</Typography>
            </>
          )
        }
      </Stack>
    );
  };
  
  const AttendanceSummary = ({ attendance }) => {
    return (
      <Stack>
        <Typography variant="caption">- {attendance.registered?.length} students registered.</Typography>
        {attendance.denied?.length > 0 && <Typography variant="caption" color={"error"}>- {attendance.denied?.length} students denied.</Typography>}
      </Stack>
    );
  }
  

  const ProgressSummary = ({ progress }) => {

    const countAnswers = (progress, status = StudentAnswerStatus.MISSING) => {
      let count = 0;

      progress.forEach(question => {
          count += question.question.studentAnswer.filter(answer => answer.status === status).length;
      });
    
      return count;
    }

    const totalAnswers = (progress) => {
      let count = 0;

      progress.forEach(question => {
          count += question.question.studentAnswer.length;
      });

      return count;
    }

    const inProgressAnswers = countAnswers(progress, StudentAnswerStatus.IN_PROGRESS)
    const submittedAnswers = countAnswers(progress, StudentAnswerStatus.SUBMITTED)

    const inProgressAnswerPercentage = Math.round((inProgressAnswers / totalAnswers(progress)) * 100)
    const submittedAnswerPercentage = Math.round((submittedAnswers / totalAnswers(progress)) * 100)

    return (
      <Stack spacing={0}>
        <Typography variant="caption">- In progress answers {inProgressAnswers} out of {totalAnswers(progress)} ({inProgressAnswerPercentage}%).</Typography>
        <Typography variant="caption">- Submitted answers {submittedAnswers} out of {totalAnswers(progress)} ({submittedAnswerPercentage}%).</Typography>
      </Stack>
    );
  }
  
  const GradingSummary = ({ results }) => {

    console.log("results", results)
  
    const countGraded = (results) => {
      let count = 0;

      results.forEach(question => {
          count += question.question.studentAnswer.filter(answer => answer.studentGrading.signedBy).length;
      });
    
      return count;
    }

    const totalGraded = (results) => {
      let count = 0;

      results.forEach(question => {
          count += question.question.studentAnswer.length;
      });

      return count;
    }

    // Signed / Total
    const graded = countGraded(results, StudentQuestionGradingStatus.GRADED)

    const gradedPercentage = Math.round((graded / totalGraded(results)) * 100)

    // awarded points / total points
    const awardedPoints = results.reduce((acc, result) => acc + result.question.studentAnswer.filter(answer => answer.studentGrading.signedBy).reduce((acc, answer) => acc + answer.studentGrading.pointsObtained, 0), 0)

    const totalPoints = results.reduce((acc, result) => acc + result.points, 0)


    // Success rate based on signed grading

    const successRate = (results) => {
      let totalPoints = 0;
      let obtainedPoints = 0;

      results.forEach(question => {
          totalPoints += question.points;
          obtainedPoints += question.question.studentAnswer
            .filter(answer => answer.studentGrading.signedBy)
            .reduce((acc, answer) => acc + answer.studentGrading.pointsObtained, 0);
      });

      return Math.round((obtainedPoints / totalPoints) * 100);
    }
  
    return (
      <Stack spacing={1}>
        <Typography variant="caption">- Graded answers {graded} out of {totalGraded(results)} ({gradedPercentage}%).</Typography>
        <Typography variant="caption">- Awarded points {awardedPoints} out of {totalPoints}.</Typography>
        <Typography variant="caption">- Success rate {successRate(results)}%.</Typography>
      </Stack>
    );
  };
  

export default EvaluationSideMenu
  