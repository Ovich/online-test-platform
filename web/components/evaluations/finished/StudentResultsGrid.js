import PiePercent from '@/components/feedback/PiePercent';
import UserAvatar from '@/components/layout/UserAvatar';
import DataGrid from '@/components/ui/DataGrid';
import { ButtonBase, Divider, Stack, Tooltip, Typography } from '@mui/material';
import React, { useState, useEffect } from 'react';
import { useTheme } from '@emotion/react';

const StudentResultsGrid = ({ evaluationToQuestions, actions, questionCellClick }) => {

  const theme = useTheme();

  const [participants, setParticipants] = useState([]);

  useEffect(() => {
    if (evaluationToQuestions && evaluationToQuestions.length > 0) {
      setParticipants(
        evaluationToQuestions[0].question.studentAnswer
          .map((sa) => sa.user)
          .sort((a, b) => a.name.localeCompare(b.name))
      );
    }
  }, [evaluationToQuestions]);

  const gridHeaders = () => {
    let q = evaluationToQuestions.map((jstq) => ({
      label: <b>{`Q${jstq.order + 1}`}</b>,
      tooltip: jstq.question.title,
      column: { width: '30px', align: 'center', minWidth: '30px' },
      renderCell: (row) =>  {    
        const data = row[`Q${jstq.order + 1}`]
        const color = data.signed ? data.successRate > 70 ? theme.palette.success.main : data.successRate > 40 ? theme.palette.info.main : theme.palette.error.main : theme.palette.grey["300"];
        const pointsObtained = data.pointsObtained;
        const totalPoints = data.totalPoints;
          return (
            <ButtonBase sx={{ padding: 1 }} onClick={(ev) => {
                ev.stopPropagation();
                questionCellClick && questionCellClick(jstq.question.id, row.participant.id)
            }}>
                <Stack display="inline-flex" alignItems="center" justifyContent="center" spacing={0.1}>
                <Typography variant="body2" sx={{ color: color }}>{`${pointsObtained}`}</Typography>
                <Divider sx={{ width:"100%", borderBottom: "1px solid", borderColor: color }} />
                <Typography variant="body2" sx={{ color: color }}>{`${totalPoints}`}</Typography>
                </Stack>
            </ButtonBase>
          )
      }
    }))


    const columns = [
        {
          label: 'Participant',
          column: { flexGrow: 1, minWidth: '200px' },
          renderCell: (row) => <UserAvatar user={row.participant} />
        }
    ]

    if (actions) {
        columns.push({
            label: 'Actions',
            column: { width: '80px', minWidth: '80px' },
            renderCell: (row) => actions(row),
        })
    }

    columns.push( {
        label: 'Success',
        column: { width: '80px', minWidth: '80px' },
        renderCell: (row) => <PiePercent
          size={60}
          value={row.participantSuccessRate}
          label={
            <Tooltip title={"Based on signed gradings"}>
                <Stack alignItems="center" justifyContent="center" spacing={0}>
                <Typography variant="body2">{`${row.obtainedPoints}`}</Typography>
                <Divider sx={{ width: '100%' }} />
                <Typography variant="caption">{`${row.totalPoints}`}</Typography>
                </Stack>
            </Tooltip>
          }
        />,
      })

    columns.push(...q)
    
    return {
      columns: columns,
    }
  }

  const gridRows = () =>
    participants.map((participant) => {
      // Initialize variables for signed evaluations
      let signedObtainedPoints = 0;
      let signedTotalPoints = 0;

      const questionColumnValues = {};

      evaluationToQuestions.forEach((jstq) => {
        const grading = jstq.question.studentAnswer.find(
          (sa) => sa.user.email === participant.email
        ).studentGrading;
        let pointsObtained = grading ? grading.pointsObtained : 0;
        let totalPoints = jstq.points;

        if (grading?.signedBy !== null) {
          // Accumulate points only for signed evaluations
          signedObtainedPoints += pointsObtained;
          signedTotalPoints += totalPoints;
        }

        let successRate = totalPoints > 0 ? Math.round((pointsObtained / totalPoints) * 100) : 0;
      
        questionColumnValues[`Q${jstq.order + 1}`] = {
          pointsObtained: pointsObtained,
          totalPoints: totalPoints,
          successRate: successRate,
          signed: grading?.signedBy !== null,
        };
      });

      // Compute participant success rate based on signed evaluations
      let participantSuccessRate =
        signedTotalPoints > 0 ? Math.round((signedObtainedPoints / signedTotalPoints) * 100) : 0;

      return {
        participant: participant,
        email: participant.email,
        participantSuccessRate: participantSuccessRate,
        obtainedPoints: signedObtainedPoints,
        totalPoints: signedTotalPoints,
        ...questionColumnValues,
        meta: {
          key: participant.email,
        },
      }
    });


  return (
    <DataGrid header={gridHeaders()} items={gridRows()} />
  );
};

export default StudentResultsGrid;
