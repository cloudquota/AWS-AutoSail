package aws

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	budgetsTypes "github.com/aws/aws-sdk-go-v2/service/budgets/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2t "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type NewbieTaskEngine struct {
	ctx      context.Context
	cfg      aws.Config
	acctID   string
	LogsChan chan string
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (e *NewbieTaskEngine) log(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	select {
	case e.LogsChan <- msg + "\n":
	default:
	}
}

func NewNewbieTaskEngine(ctx context.Context, ak, sk, proxy string) (*NewbieTaskEngine, error) {
	hc, err := baseHTTPClient(proxy)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-1"), // 新手任务固定跑 us-east-1
		config.WithCredentialsProvider(aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(ak, sk, ""))),
		config.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}

	stsCli := sts.NewFromConfig(cfg)
	idOut, err := stsCli.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("获取账户 ID 失败: %v", err)
	}

	return &NewbieTaskEngine{
		ctx:      ctx,
		cfg:      cfg,
		acctID:   *idOut.Account,
		LogsChan: make(chan string, 200),
	}, nil
}

func (e *NewbieTaskEngine) RunAll() {
	defer close(e.LogsChan)
	e.log("====== 💰 自动执行 AWS 新手任务 (赚取 $80 抵扣金) ======")
	e.log("区域：强制使用 us-east-1 (账户 ID: %s)", e.acctID)

	e.taskSetBudget()
	e.taskRunEC2()
	e.taskRunLambda()
	e.taskRunRDS()

	e.log("====== 🎉 所有流程执行完毕 ======")
}

func (e *NewbieTaskEngine) taskSetBudget() {
	e.log("\n[任务 1/4] 正在设置 AWS Cost Budget (成本预算)...")
	cli := budgets.NewFromConfig(e.cfg)
	budgetName := fmt.Sprintf("AutoBudget-%s", randStr(6))
	email := fmt.Sprintf("alert-%s@gmail.com", randStr(4))

	_, err := cli.CreateBudget(e.ctx, &budgets.CreateBudgetInput{
		AccountId: aws.String(e.acctID),
		Budget: &budgetsTypes.Budget{
			BudgetName:  aws.String(budgetName),
			BudgetType:  budgetsTypes.BudgetTypeCost,
			TimeUnit:    budgetsTypes.TimeUnitMonthly,
			BudgetLimit: &budgetsTypes.Spend{Amount: aws.String("10.0"), Unit: aws.String("USD")},
		},
		NotificationsWithSubscribers: []budgetsTypes.NotificationWithSubscribers{
			{
				Notification: &budgetsTypes.Notification{
					NotificationType:   budgetsTypes.NotificationTypeActual,
					ComparisonOperator: budgetsTypes.ComparisonOperatorGreaterThan,
					Threshold:          80.0,
				},
				Subscribers: []budgetsTypes.Subscriber{{SubscriptionType: budgetsTypes.SubscriptionTypeEmail, Address: aws.String(email)}},
			},
		},
	})

	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			e.log(" ✅ 预算已存在，跳过。")
		} else {
			e.log(" ❌ 失败: %v", err)
		}
	} else {
		e.log(" ✅ 预算 [%s] 创建成功", budgetName)
	}
}

func (e *NewbieTaskEngine) taskRunEC2() {
	e.log("\n[任务 2/4] 正在启动 EC2 实例...")
	cli := ec2.NewFromConfig(e.cfg)
	ami := "ami-051f7e7f6c2f40dc1"

	runOut, err := cli.RunInstances(e.ctx, &ec2.RunInstancesInput{
		ImageId:      aws.String(ami),
		InstanceType: ec2t.InstanceTypeT3Micro,
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
	})
	if err != nil {
		e.log(" ❌ 启动失败: %v", err)
		return
	}

	id := *runOut.Instances[0].InstanceId
	e.log(" ⏳ 实例 %s 启动中，等待 Running...", id)

	for i := 0; i < 40; i++ {
		time.Sleep(3 * time.Second)
		desc, _ := cli.DescribeInstances(e.ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
		if len(desc.Reservations) > 0 && desc.Reservations[0].Instances[0].State.Name == ec2t.InstanceStateNameRunning {
			e.log(" ✅ 状态: Running (任务达成)")
			break
		}
		e.log("...")
	}

	e.log(" 🗑️ 正在终止实例...")
	cli.TerminateInstances(e.ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{id}})
	e.log(" ✅ 实例 %s 已终止", id)
}

func (e *NewbieTaskEngine) taskRunLambda() {
	e.log("\n[任务 3/4] 正在创建并调用 Lambda 函数...")
	iamCli := iam.NewFromConfig(e.cfg)
	roleName := fmt.Sprintf("AutoLambdaRole-%s", randStr(5))
	assumeRolePolicy := `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "lambda.amazonaws.com"},"Action": "sts:AssumeRole"}]}`

	e.log(" -> 创建临时 IAM 角色: %s", roleName)
	roleOut, err := iamCli.CreateRole(e.ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(assumeRolePolicy),
	})
	if err != nil {
		e.log(" ❌ IAM 角色创建失败: %v", err)
		return
	}
	roleArn := *roleOut.Role.Arn
	e.log(" ⏳ 等待 IAM 角色生效 (约10秒)...")
	time.Sleep(10 * time.Second)

	code := `def lambda_handler(event, context): return "Hello AWS 80 USD"`
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	f, _ := zipWriter.Create("lambda_function.py")
	f.Write([]byte(code))
	zipWriter.Close()

	lambdaCli := lambda.NewFromConfig(e.cfg)
	funcName := fmt.Sprintf("AutoFunc-%s", randStr(5))
	
	// Create function
	_, err = lambdaCli.CreateFunction(e.ctx, &lambda.CreateFunctionInput{
		FunctionName: aws.String(funcName),
		Runtime:      lambdaTypes.RuntimePython39,
		Role:         aws.String(roleArn),
		Handler:      aws.String("lambda_function.lambda_handler"),
		Code:         &lambdaTypes.FunctionCode{ZipFile: buf.Bytes()},
	})

	if err != nil {
		time.Sleep(5 * time.Second)
		_, err = lambdaCli.CreateFunction(e.ctx, &lambda.CreateFunctionInput{
			FunctionName: aws.String(funcName),
			Runtime:      lambdaTypes.RuntimePython39,
			Role:         aws.String(roleArn),
			Handler:      aws.String("lambda_function.lambda_handler"),
			Code:         &lambdaTypes.FunctionCode{ZipFile: buf.Bytes()},
		})
		if err != nil {
			e.log(" ❌ 函数创建失败: %v", err)
			iamCli.DeleteRole(e.ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
			return
		}
	}

	e.log(" ✅ 函数 %s 创建成功，正在初始化...", funcName)
	e.log(" ⏳ 等待函数就绪 (Pending -> Active)")

	for i := 0; i < 30; i++ {
		fOut, err := lambdaCli.GetFunction(e.ctx, &lambda.GetFunctionInput{FunctionName: aws.String(funcName)})
		if err == nil && fOut.Configuration.State == lambdaTypes.StateActive {
			e.log(" ✅ 就绪")
			break
		}
		time.Sleep(2 * time.Second)
		e.log("...")
	}

	_, err = lambdaCli.Invoke(e.ctx, &lambda.InvokeInput{FunctionName: aws.String(funcName)})
	if err == nil {
		e.log(" ✅ 调用成功！任务达成。")
	} else {
		e.log(" ❌ 调用失败: %v", err)
	}

	e.log(" 🗑️ 清理资源...")
	lambdaCli.DeleteFunction(e.ctx, &lambda.DeleteFunctionInput{FunctionName: aws.String(funcName)})
	iamCli.DeleteRole(e.ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
	e.log(" ✅ Lambda 相关资源已清理")
}

func (e *NewbieTaskEngine) taskRunRDS() {
	e.log("\n[任务 4/4] 正在创建 RDS 数据库 (MySQL Free Tier)...")
	e.log("⚠️ 警告：RDS 创建非常慢 (5-10 分钟)，流式输出可能较长时间不刷新。")
	rdsCli := rds.NewFromConfig(e.cfg)
	dbName := fmt.Sprintf("db-%s", randStr(6))
	masterUser := "admin"
	masterPass := "Password123456"

	_, err := rdsCli.CreateDBInstance(e.ctx, &rds.CreateDBInstanceInput{
		DBInstanceIdentifier:  aws.String(dbName),
		DBInstanceClass:       aws.String("db.t3.micro"),
		Engine:                aws.String("mysql"),
		MasterUsername:        aws.String(masterUser),
		MasterUserPassword:    aws.String(masterPass),
		AllocatedStorage:      aws.Int32(20),
		BackupRetentionPeriod: aws.Int32(0),
	})
	if err != nil {
		e.log(" ❌ 创建请求失败: %v", err)
		return
	}
	defer e.cleanupRDSInstance(rdsCli, dbName)

	e.log(" ⏳ 数据库 %s 正在创建...", dbName)
	
	maxWait := 30
	created := false
	for i := 0; i < maxWait; i++ {
		time.Sleep(30 * time.Second)
		
		out, err := rdsCli.DescribeDBInstances(e.ctx, &rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(dbName),
		})
		if err != nil {
			e.log("...")
			continue
		}
		if len(out.DBInstances) > 0 {
			status := aws.ToString(out.DBInstances[0].DBInstanceStatus)
			e.log(" [%s] ", status)
			if status == "available" {
				created = true
				e.log("\n ✅ 数据库已就绪！任务达成。")
				break
			}
		}
	}

	if !created {
		e.log("\n ⚠️ 等待超时，数据库可能仍在创建中，接下来会继续自动重试删除。")
	}
}

func (e *NewbieTaskEngine) cleanupRDSInstance(rdsCli *rds.Client, dbName string) {
	e.log(" 🗑️ 开始清理数据库 %s ...", dbName)

	deleteRequested := false
	for attempt := 1; attempt <= 24; attempt++ {
		out, err := rdsCli.DescribeDBInstances(e.ctx, &rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(dbName),
		})
		if err != nil {
			if isRDSInstanceNotFound(err) {
				e.log(" ✅ 数据库 %s 已删除。", dbName)
				return
			}
			e.log(" ⚠️ 第 %d 次检查数据库状态失败: %v", attempt, err)
			time.Sleep(20 * time.Second)
			continue
		}
		if len(out.DBInstances) == 0 {
			e.log(" ✅ 数据库 %s 已删除。", dbName)
			return
		}

		status := strings.ToLower(aws.ToString(out.DBInstances[0].DBInstanceStatus))
		if status == "deleting" {
			if !deleteRequested {
				e.log(" ⏳ 数据库已经进入 deleting 状态，继续等待删除完成...")
				deleteRequested = true
			} else {
				e.log(" ⏳ 删除进行中，当前状态: %s", status)
			}
			time.Sleep(30 * time.Second)
			continue
		}

		_, err = rdsCli.DeleteDBInstance(e.ctx, &rds.DeleteDBInstanceInput{
			DBInstanceIdentifier:  aws.String(dbName),
			SkipFinalSnapshot:     aws.Bool(true),
			DeleteAutomatedBackups: aws.Bool(true),
		})
		if err == nil {
			deleteRequested = true
			e.log(" ✅ 删除指令已发送，当前状态: %s", status)
			time.Sleep(30 * time.Second)
			continue
		}

		if isRDSDeleteRetryable(err) {
			e.log(" ⏳ 当前状态 %s 暂时还不能删除，稍后重试...", status)
			time.Sleep(30 * time.Second)
			continue
		}

		e.log(" ❌ 自动删除数据库失败: %v", err)
		return
	}

	e.log(" ⚠️ 数据库 %s 清理重试超时，请稍后到控制台确认是否已删除。", dbName)
}

func isRDSInstanceNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "dbinstancenotfound") || strings.Contains(msg, "db instance not found")
}

func isRDSDeleteRetryable(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invaliddbinstancestate") ||
		strings.Contains(msg, "is not in available state") ||
		strings.Contains(msg, "is not in deleting state") ||
		strings.Contains(msg, "cannot delete") ||
		strings.Contains(msg, "creating")
}
